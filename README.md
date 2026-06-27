# FuckYouDaoADB

有道词典笔 ADB 密码修改工具

## 原理

OTA 中间人攻击 + 固件重打包:
1. 抓取词典笔的 `checkVersion` 请求
2. 伪造 `version=99.99.90` 重放到云端
3. 下载最新固件,扫描并替换密码哈希 (MD5/SHA256)
4. 改 hosts 把 `iotapi.abupdate.com` 劫持到本机
5. 起 HTTP 服务喂固件给笔

## 安装

```bash
# Windows: 先装 Npcap
# https://npcap.com/

pip install scapy requests
```

## 使用

```bash
# 1. 开启 Windows 移动热点(默认 192.168.137.1)
# 2. 词典笔连到此热点
# 3. 以管理员权限运行:
python paper.py --verbose

# 跳过抓包(测试用):
python paper.py --skip-capture \
    --test-ota-url /product/1708583443/f730c7fa72bd3871/ota/checkVersion \
    --test-ota-body '{"timestamp":1755184821,"sign":"...","mid":"...","productId":"1708583443","version":"4.7.7","networkType":"WIFI"}'
```
