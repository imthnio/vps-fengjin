# VPS 出口封禁工具（vps-fengjin）

让**这台 Linux 服务器自己**访问不了指定的网站域名、IP 或网段。你在服务器上搭建的代理节点（任意端口、任意协议）替用户向外发起连接，也算这台服务器自己发出的连接，因此可以直接用来屏蔽广告、特定网站或 App。

64MB 内存的小鸡也能跑：不装大软件，临时文件放在硬盘上不挤占内存盘；内存 ≤ 192MB 时自动开启内存超卖，磁盘够用再自动加 64MB 交换空间。

## 一键安装 / 更新（root 运行）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "dnf install -y" "yum install -y" "pacman -Sy --noconfirm" "zypper --non-interactive install" "opkg install"; do b=${pm%% *}; c $b || continue; [ "$b" = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-fengjin/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-fengjin@main/install.sh; do (wget -qO /tmp/vps-fengjin.sh "$u" || curl -fsSL -o /tmp/vps-fengjin.sh "$u") 2>/dev/null && [ -s /tmp/vps-fengjin.sh ] && head -n 1 /tmp/vps-fengjin.sh | grep -q "^#!/bin/sh" && grep -q vps-fengjin-onekey-begin /tmp/vps-fengjin.sh && { ok=1; break; }; rm -f /tmp/vps-fengjin.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/vps-fengjin.sh'
```

> 再次运行上面的一键命令即自动更新到最新版，原有配置和名单都会完整保留。

## 首次使用：只需 2 步

脚本会自动检测系统和防火墙能力，然后进入大白话 2 步向导（所有选项 `0` 统一表示返回/取消，直接回车即推荐项）：

1. **添加你要封禁的网站或 IP**
   - 可以**直接在菜单里输入域名或 IP**（如 `baidu.com` 或 `baidu.com, qq.com, 1.2.3.4`），或批量粘贴（输完另起一行输入 `ok` 或 `完成` 回车）。
   - 可以**直接粘贴在线名单链接**（GitHub 普通网页链接会自动转成 Raw 直链，不用自己找 Raw 按钮）。
   - 可以**导入服务器本地文件**（如 `/root/block.txt`）。
   - 支持添加多份名单，每份独立保存，支持预览内容、重命名、删除。
   - 单个名单最大 32MB；内存 ≤ 192MB 最多支持 10 万个域名，更大内存支持 50 万个域名。
2. **核对并生效**
   - 清晰列出域名/IP 数量、示例条目、生效范围与防误封保护，直接回车立即生效；也可随时返回修改名单、调整高级端口范围或取消退出。

默认**全局封禁**（本机及所有代理节点均无法访问，**不用填写节点端口**）。只有极少数场景只想封对方网站的某些目标端口（例如只封 443）时，才需要在核对页或菜单里进入“高级设置”。

## 支持的名单格式（可混写）

```text
baidu.com
baidu.com, qq.com, 1.2.3.4
*.example.com
.example.com
+.example.com
https://www.example.com/path
1.2.3.4
1.2.3.0/24
DOMAIN,www.example.com
DOMAIN-SUFFIX,example.com
IP-CIDR,1.2.3.0/24,no-resolve
IP-CIDR6,2001:db8::/32,no-resolve
- 'DOMAIN-SUFFIX,example.com'
0.0.0.0 example.com
||example.com^
address=/example.com/0.0.0.0
full:www.example.com
domain:example.com
```

- Clash YAML（`payload:` 开头、`- ` 列表项、单双引号）、AdGuard / EasyList、Hosts、v2fly / geosite、带 BOM 或 Windows 换行的文件均自动识别。
- 比 `/16` 更宽的 IPv4 网段与比 `/32` 更宽的 IPv6 网段会自动跳过，避免误写导致整机断网。
- **防误封保护**：自动跳过你当前的 SSH 登录来源（含 `sudo` 场景、IPv6 及自定义 SSH 端口）、本机网卡地址、本机上游 DNS，不会把自己锁在外面。

## 日常管理与常用命令

安装完成后，随时输入 `vps-fengjin` 打开管理菜单：
- 查看运行状态与规则健康度（若被 UFW/firewalld 重载冲掉会立即提示）
- 添加封禁、查看与管理名单（**预览内容** / **一键更新在线链接** / 改名 / 删除）
- **实测验证**：输入任意网址或 IP，立刻告诉你是否命中名单及是否已被成功拦截
- 一键暂停 / 开启封禁（保留名单）、更换整套名单、高级范围设置、彻底卸载

也可以直接在终端使用子命令：

```sh
vps-fengjin                     打开管理菜单
vps-fengjin status              查看详细状态与规则实时检查
vps-fengjin test baidu.com      实测某个网站或 IP 是否已被封住
vps-fengjin update-lists        重新下载所有在线链接名单并生效
vps-fengjin refresh             按已存名单重新生效
vps-fengjin on | off            开启 / 暂停封禁（保留名单）
vps-fengjin purge               彻底卸载
vps-fengjin check 名单或网址     只检查名单内容，不改防火墙
```

## 参数化无交互运行（适合批量部署）

```sh
sh /tmp/vps-fengjin.sh -l https://example.com/block.list -y
sh /tmp/vps-fengjin.sh -l /root/a.txt -l /root/b.txt -p 80,443 --replace -y
cat list.txt | sh /tmp/vps-fengjin.sh -l - -y
```

```text
-l, --list 名单    名单网址或文件路径，可写多次；写 - 表示从标准输入读
-a, --all          全局封禁（默认）
-p, --ports 端口   仅封这些目标端口，例如 80,443（仅对 IP/网段生效）
    --replace      替换原有全部名单（默认是追加）
-y, --yes          跳过确认，直接生效
```

## 拦截原理与边界

- **域名不误伤同 IP 网站**：域名仅在 DNS 解析层拦截（含所有子域名），不封解析出来的 IP，共用同一 CDN/IP 的正常网站不受影响；名单里直接写的 IP / 网段走防火墙拦截。
- **高性能低开销**：400 个以内域名且支持 `iptables` 字符串匹配时，使用独立子链仅对 53 端口 DNS 查询做匹配（不改系统 DNS，普通代理流量几乎零开销）；大名单、nftables 或无防火墙权限的机器自动使用轻量的 `dnsmasq`（已兼容 Ubuntu 等 `systemd-resolved` 环境，关闭/卸载时原样恢复），兜底才写入 `/etc/hosts`。
- **原子切换、无空档、失败自动回滚**：通过 `iptables-restore --noflush`、`ipset swap`、`nft` 事务一次性替换规则；若生效失败会自动还原修改前的全部配置与规则。
- **开机自启与定时巡检**：重启后自动恢复封禁，并每 6 小时自动巡检一次防止规则被其他防火墙重载清除。
- **受限容器（无 NET_ADMIN 权限）**：自动切换为“仅封禁域名”模式；名单里的 IP/网段会跳过。若代理程序自行指定了 DoH/DoT 加密 DNS，可能绕过 DNS 层拦截；容器重启后如未自动恢复，运行 `vps-fengjin on` 即可。
