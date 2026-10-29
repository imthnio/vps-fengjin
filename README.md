# 封禁服务器访问指定网站

在一台新的 Linux 服务器上运行一次。脚本自己认出系统，问你名单，再问封整台机器还是只封某些目标端口，确认后生效。也可以用参数一次跑完，不提问。

作用是让**这台服务器自己**访问不了名单里的域名、IP 或网段。代理程序替用户连出去，也算这台服务器自己发出的连接。

64MB 内存的小鸡可以跑。脚本不装大软件。内存不超过约 192MB 时，会允许内存超卖；磁盘还够的话，再加 64MB 交换空间。

## 安装（用 root 运行，一行）

```sh
sh -c 'c(){ command -v "$1" >/dev/null 2>&1; }; c curl || c wget || { for pm in "apk add --no-cache" "apt-get install -y" "dnf install -y" "yum install -y" "pacman -Sy --noconfirm" "zypper --non-interactive install" "opkg install"; do b=${pm%% *}; c $b || continue; [ "$b" = apt-get ] && { apt-get update -qq 2>/dev/null || sudo apt-get update -qq 2>/dev/null; }; $pm curl wget ca-certificates 2>/dev/null || sudo $pm curl wget ca-certificates 2>/dev/null; break; done; c curl || c wget || { echo "装不上 curl / wget，请手动装一个"; exit 1; }; }; ok=""; for u in https://raw.githubusercontent.com/imthnio/vps-fengjin/main/install.sh https://cdn.jsdelivr.net/gh/imthnio/vps-fengjin@main/install.sh; do (wget -qO /tmp/vps-fengjin.sh "$u" || curl -fsSL -o /tmp/vps-fengjin.sh "$u") 2>/dev/null && [ -s /tmp/vps-fengjin.sh ] && head -n 1 /tmp/vps-fengjin.sh | grep -q "^#!/bin/sh" && grep -q vps-fengjin-onekey-begin /tmp/vps-fengjin.sh && { ok=1; break; }; rm -f /tmp/vps-fengjin.sh; done; [ -n "$ok" ] || { echo "下载 install.sh 失败，请检查网络"; exit 1; }; sh /tmp/vps-fengjin.sh'
```

## 它会问什么

第一次运行一共三步，每一步都有默认值，直接回车就是推荐的选项：

1. **添加名单**。可以填网址、这台机器上的文件路径，或者直接粘贴（粘贴完另起一行输入 `END`）。在菜单提示处直接粘贴网址也行。可以加好几份，每份自动起名字，能查看、改名、删掉刚加的。一行一个，域名和 IP 可以混在一起。
   名单文件最大 32MB。内存 192MB 以下（包括 64MB 小鸡）最多 10 万个域名，更大的机器最多 50 万个，整份去广告名单也吃得下。临时文件放在硬盘上，不占内存盘。
2. **封禁范围**。
   - 整台机器（默认）：不管哪个端口，都不让访问名单里的地址。
   - 只封指定的目标端口：例如 `443`，或 `80,443`，最多 30 个。别的端口还能连。

   这里的端口是**对方网站的端口**，不是这台机器对外开的端口。
3. **确认**。列出要封的条数和范围，输入 `y` 才会改防火墙；其他输入都算取消，什么都不改。

输错了会提示重输，不会退出；输入中途断了（例如管道里的答案不够），会明确告诉你，不会卡住。

支持这些写法：

```text
example.com
*.example.com
.example.com
1.2.3.4
1.2.3.0/24
DOMAIN-SUFFIX,example.com
IP-CIDR,1.2.3.0/24
IP-CIDR6,2001:db8::/32,no-resolve
+.example.com
- 'DOMAIN-SUFFIX,example.com'
0.0.0.0 example.com
||example.com^
```

Clash 的 YAML 名单（以 `payload:` 开头、每行前面有 `- `，带不带引号都行）也能直接用。文件开头的隐藏标记（BOM）和 Windows 换行会自动忽略。

`/16` 比这更宽的 IPv4 网段，以及 `/32` 比这更宽的 IPv6 网段，会跳过。这样一份写错的名单不会把整台机器的出口封死。

这些地址永远不封，名单里包含它们的条目会跳过并提示：你当前的 SSH 来源（也会从正在连着 sshd 的连接里找，包括改过的 SSH 端口）、本机地址、本机用的 DNS 服务器。

## 不提问，直接用参数跑

适合批量部署或写进别的脚本：

```sh
sh /tmp/vps-fengjin.sh -l https://example.com/block.list -y
sh /tmp/vps-fengjin.sh -l /root/a.txt -l /root/b.txt -p 80,443 --replace -y
cat list.txt | sh /tmp/vps-fengjin.sh -l - -y
```

```text
-l, --list 名单    名单网址或文件路径，可以写多次；写 - 表示从标准输入读
-a, --all          封整台机器（默认）
-p, --ports 端口   只封这些目标端口，例如 80,443
    --replace      换掉原来的名单（默认是追加到原来的名单里）
-y, --yes          不再确认，直接生效
```

不加 `-y` 时仍然会问一次确认。

## 封完以后

再运行 `vps-fengjin` 是一个菜单：重新生效、追加名单、管理名单（查看、改名、删除）、换一套新名单、修改封禁范围、关闭、彻底删除。

```sh
vps-fengjin status          查看（包括规则是不是被别的防火墙清掉了）
vps-fengjin refresh         域名重新解析后再封一次
vps-fengjin on              按保存的名单重新打开
vps-fengjin off             关闭，名单留着
vps-fengjin purge           彻底删除
sh install.sh check 名单.txt  只检查这份名单，不改防火墙
```

**更新**：再运行一次上面的一键安装命令就是更新。名单和设置都会留着，脚本会提示从哪个版本更新到哪个版本，并问要不要马上用新版本重新生效。

重启后会按上次保存的结果自动再封上。名单里有域名时，大约每 6 小时重新解析一次。

**改规则不会出现空档**：每次生效都是先把新规则准备好，再一次性换上（iptables-restore、ipset swap、nft 事务）。新规则加不上时，原来的规则和设置都原样恢复。

## 域名怎么封

- 整台机器封域名时，优先拦截发往 53 端口的域名查询（大小写混写也拦得住），不改本机的 DNS 设置。域名多于 400 个时改用 dnsmasq，不行再写入 `/etc/hosts`。域名当前解析到的 IP 也会封掉。几家网站共用同一个 IP 时，可能误伤。
- 按端口封域名时，只能封这次解析到的 IP。后缀不超过 5000 个时会顺带解析 `www.`。新的子域名要等下次刷新。
- 解析是几路同时查的，每路一次把一批域名交给 `dig`，几万个域名也能较快跑完。路数按内存定：128MB 以下 4 路，512MB 以下 8 路，更大 16 路。会先挑一个能用的 DNS 服务器（本机配置的优先）。

## 边界

- 只拦这台机器自己发出去的连接。它只是把别人的流量原样转发出去时，不拦。
- 走加密 DNS（443 或 853 上的 DoH、DoT）的程序，可能绕过“拦域名查询”。整台机器模式下，已经解析到的 IP 仍然封着。
- 有 iptables 但没有 ipset 时（常见于部分 NAT 小鸡），地址得一条条写进规则，按内存给了上限（128MB 以下约 1500 条，内存越大上限越高），超出部分不拦。
- 默认的 iptables 用不了时（NAT 小鸡上常见：系统自带的是 nft 版，内核不支持），会自动改用 `iptables-legacy`，再不行才用 nftables。
- 实在改不了防火墙时，脚本会打印真实报错，并按机器类型（OpenVZ、Docker、LXC）说明要找商家开什么权限。
- 别的防火墙（firewalld、ufw）重载时可能清掉规则。`vps-fengjin status` 会提示，`refresh` 或下一次定时刷新会重新封上。

## 赞赏支持
如果这个脚本帮到了你，欢迎请我喝杯咖啡 ☕  
微信扫一扫下方赞赏码即可：

![赞赏码](./appreciate.png)

