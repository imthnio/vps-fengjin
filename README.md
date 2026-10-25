# 封禁服务器访问指定网站

在一台新的 Linux 服务器上运行一次。脚本自己认出系统，问你名单，再问封一个目标端口、多个目标端口，还是整台机器。

作用是让**这台服务器自己**访问不了名单里的域名、IP 或网段。代理程序替用户连出去，也算这台服务器自己发出的连接。

64MB 内存的小鸡可以跑。脚本不装大软件。内存不超过约 192MB 时，会允许内存超卖；磁盘还够的话，再加 64MB 交换空间。

## 安装（用 root 运行，一行）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "dnf install -y" "yum install -y" "pacman -Sy --noconfirm" "zypper --non-interactive install" "opkg install"; do b=${pm%% *}; c $b || continue; [ "$b" = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-fengjin/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-fengjin@main/install.sh; do (wget -qO /tmp/vps-fengjin.sh "$u" || curl -fsSL -o /tmp/vps-fengjin.sh "$u") 2>/dev/null && [ -s /tmp/vps-fengjin.sh ] && head -n 1 /tmp/vps-fengjin.sh | grep -q "^#!/bin/sh" && grep -q vps-fengjin-onekey-begin /tmp/vps-fengjin.sh && { ok=1; break; }; rm -f /tmp/vps-fengjin.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/vps-fengjin.sh'
```

## 它会问什么

1. 名单从哪来。可以粘贴、读这台机器上的文件，或填一个网址。可以加好几份。一行一个，域名和 IP 可以混在一起。
   名单大小按内存放宽：192MB 以下最多 3MB、2 万条；768MB 以下最多 12MB、15 万条；再大最多 32MB、50 万条，整份去广告名单也吃得下。
2. 封在什么范围。
   - 一个目标端口：例如只填 `443`。这台机器用别的端口仍可能连上这些地址。
   - 多个目标端口：例如 `80,443`。
   - 整台机器：不管哪个端口，都不让访问名单里的地址。

这里的端口是**对方网站的端口**，不是这台机器对外开的端口。

支持这些写法：

```text
example.com
*.example.com
.example.com
1.2.3.4
1.2.3.0/24
DOMAIN-SUFFIX,example.com
IP-CIDR,1.2.3.0/24
0.0.0.0 example.com
||example.com^
```

`/16` 比这更宽的 IPv4 网段，以及 `/32` 比这更宽的 IPv6 网段，会跳过。这样一份写错的名单不会把整台机器的出口封死。你当前 SSH 的来源地址、本机地址也会跳过。

## 封完以后

再运行 `vps-fengjin` 可以追加名单、换名单、查看或关闭。

```sh
vps-fengjin status          查看
vps-fengjin refresh         域名重新解析后再封一次
vps-fengjin off             关闭，名单留着
vps-fengjin purge           彻底删除
sh install.sh check 名单.txt  只检查这份名单，不改防火墙
```

重启后会按上次保存的结果自动再封上。名单里有域名时，大约每 6 小时重新解析一次。

## 边界

- 只拦这台机器自己发出去的连接。它只是把别人的流量原样转发出去时，不拦。
- 整台机器封域名时，优先拦截发往 53 端口的域名查询，不改本机的 DNS 设置。域名当前解析到的 IP 也会封掉。几家网站共用同一个 IP 时，可能误伤。
- 按端口封域名时，只能封这次解析到的 IP。新的子域名要等下次刷新。
- 走加密 DNS（443 或 853 上的 DoH、DoT）的程序，可能绕过“拦域名查询”。整台机器模式下，已经解析到的 IP 仍然封着。
- 被切出来、不能改防火墙的小鸡，脚本会说明封不了。

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)

