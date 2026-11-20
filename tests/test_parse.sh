#!/bin/sh
# 全面逻辑与交互测试（无需 root，不修改系统防火墙）。
cd "$(dirname "$0")/.." || exit 1
VPS_FENGJIN_LIB=1
. ./install.sh

fail=0

eq() {
  name=$1
  got=$2
  want=$3
  if [ "$got" = "$want" ]; then
    printf 'ok %s\n' "$name"
  else
    printf 'FAIL %s\n got [%s]\n want [%s]\n' "$name" "$got" "$want" >&2
    fail=$((fail + 1))
  fi
}

classify() {
  printf '%s\n' "$1" | fengjin_awk classify | LC_ALL=C sort
}

# --- 1. 名单解析测试 ---
eq "domain" "$(classify 'Example.COM')" "domain	example.com"
eq "suffix star" "$(classify '*.Example.COM')" "suffix	example.com"
eq "suffix dot" "$(classify '.example.com')" "suffix	example.com"
eq "ipv4" "$(classify '1.2.3.4')" "ip4	1.2.3.4"
eq "cidr normalize" "$(classify '1.2.3.5/24')" "net4	1.2.3.0/24"
eq "cidr20" "$(classify '172.16.5.9/20')" "net4	172.16.0.0/20"
eq "wide v4" "$(classify '1.2.3.0/8')" "bad	wide	1.2.3.0/8"
eq "wide zero" "$(classify '0.0.0.0/0')" "bad	wide	0.0.0.0/0"
eq "local v4" "$(classify '127.0.0.1')" "bad	local	127.0.0.1"
eq "double slash cidr" "$(classify '1.2.3.4/24/32')" "bad	parse	1.2.3.4/24/32"
eq "comment" "$(classify '# hello')" ""
eq "semicolon comment" "$(classify '; bind comment')" ""
eq "slash comment" "$(classify '// js comment')" ""
eq "hosts" "$(classify '0.0.0.0 example.com foo.com')" "$(printf '%s\n' 'domain	example.com' 'domain	foo.com')"
eq "hosts boilerplate zero" "$(classify '0.0.0.0 0.0.0.0')" ""
eq "hosts boilerplate localhost" "$(classify '127.0.0.1 localhost localhost.localdomain')" ""
eq "numeric tld rejected" "$(classify 'foo.123')" "bad	parse	foo.123"
eq "adblock" "$(classify '||Example.com^')" "suffix	example.com"
eq "clash suffix" "$(classify 'DOMAIN-SUFFIX,Example.com,PROXY')" "suffix	example.com"
eq "clash domain" "$(classify 'DOMAIN,www.example.com')" "domain	www.example.com"
eq "clash cidr" "$(classify 'IP-CIDR,10.1.2.0/24,no-resolve')" "net4	10.1.2.0/24"
eq "clash cidr6" "$(classify 'IP-CIDR6,2001:db8::/32')" "net6	2001:db8::/32"
eq "url" "$(classify 'https://www.Example.com/a/b')" "domain	www.example.com"
eq "bare url with path" "$(classify 'www.Baidu.com/s?wd=test')" "domain	www.baidu.com"
eq "dnsmasq" "$(classify 'address=/example.com/0.0.0.0')" "suffix	example.com"
eq "v2fly full" "$(classify 'full:api.Example.com @ads')" "domain	api.example.com"
eq "v2fly domain" "$(classify 'domain:Example.com @cn')" "suffix	example.com"
eq "v2fly keyword" "$(classify 'keyword:abc')" "bad	keyword	keyword:abc"
eq "v2fly regexp" "$(classify 'regexp:^ads\.')" "bad	unsupported	regexp:^ads\."
eq "keyword" "$(classify 'DOMAIN-KEYWORD,abc')" "bad	keyword	DOMAIN-KEYWORD,abc"
eq "junk" "$(classify 'not a domain')" "bad	parse	not a domain"
eq "beginner multi comma" "$(classify 'baidu.com, qq.com, 1.2.3.4')" "$(printf '%s\n' 'domain	baidu.com' 'domain	qq.com' 'ip4	1.2.3.4')"
eq "beginner multi cn comma" "$(classify 'baidu.com，qq.com、weibo.com')" "$(printf '%s\n' 'domain	baidu.com' 'domain	qq.com' 'domain	weibo.com')"
eq "beginner multi space" "$(classify 'baidu.com qq.com 1.2.3.4')" "$(printf '%s\n' 'domain	baidu.com' 'domain	qq.com' 'ip4	1.2.3.4')"
eq "ipv6" "$(classify '2001:DB8::1')" "ip6	2001:db8::1"
eq "local v6" "$(classify '::1')" "bad	local	::1"
eq "wide v6" "$(classify '2001:db8::/16')" "bad	wide	2001:db8::/16"
eq "link local" "$(classify 'fe80::1')" "bad	local	fe80::1"
eq "cidr6 normalize" "$(classify '2001:db8:1234::5/32')" "net6	2001:db8::/32"
eq "cidr6 nibble" "$(classify '2001:db8:abcd:ef12::/50')" "net6	2001:db8:abcd:c000::/50"
eq "cidr6 keep" "$(classify '2400:cb00:1:2::/64')" "net6	2400:cb00:1:2::/64"
eq "ip as suffix" "$(classify 'DOMAIN-SUFFIX,103.21.91.144')" "ip4	103.21.91.144"
eq "ip6 as domain" "$(classify 'DOMAIN,2001:db8::7')" "ip6	2001:db8::7"
eq "numeric label ok" "$(classify '1.2.3.example.com')" "domain	1.2.3.example.com"
eq "user sample" "$(printf '%s\n' 'DOMAIN,123.4456.com,' 'DOMAIN-SUFFIX,123.com' 'IP-CIDR,1.211.111.0/22,no-resolve' 'IP-CIDR6,2a01:1110:f000::/36,no-resolve' | fengjin_awk classify)" "$(printf '%s\n' 'domain	123.4456.com' 'suffix	123.com' 'net4	1.211.108.0/22' 'net6	2a01:1110:f000::/36')"
eq "bom first line" "$(printf '\357\273\277DOMAIN,example.com\n' | fengjin_awk classify)" "domain	example.com"
eq "crlf" "$(printf 'DOMAIN-SUFFIX,example.com\r\n' | fengjin_awk classify)" "suffix	example.com"
eq "yaml payload" "$(printf '%s\n' 'payload:' "  - 'DOMAIN-SUFFIX,example.com'" '  - "IP-CIDR,10.1.2.0/24,no-resolve"' '  - DOMAIN,www.example.org' | fengjin_awk classify)" "$(printf '%s\n' 'suffix	example.com' 'net4	10.1.2.0/24' 'domain	www.example.org')"
eq "yaml plain cidr" "$(printf '%s\n' "- '1.0.1.0/24'" | fengjin_awk classify)" "net4	1.0.1.0/24"
eq "fullwidth comma" "$(printf '%s\n' 'DOMAIN，example.com' | fengjin_awk classify)" "domain	example.com"
eq "plus dot" "$(printf '%s\n' '+.Example.com' | fengjin_awk classify)" "suffix	example.com"
eq "wire" "$(printf '%s\n' example.com | fengjin_awk wire)" "076578616d706c6503636f6d"

# --- 2. GitHub URL 自动转换 ---
eq "gh blob to raw" "$(normalize_url 'https://github.com/imthnio/vps-fengjin/blob/main/list.txt')" "https://raw.githubusercontent.com/imthnio/vps-fengjin/main/list.txt"
eq "gh blob query" "$(normalize_url 'https://github.com/u/r/blob/main/a/b.list?raw=1')" "https://raw.githubusercontent.com/u/r/main/a/b.list"
eq "gh raw to raw" "$(normalize_url 'https://github.com/u/r/raw/main/a.txt')" "https://raw.githubusercontent.com/u/r/main/a.txt"
eq "non-gh unchanged" "$(normalize_url 'https://example.com/blob/list.txt')" "https://example.com/blob/list.txt"

# --- 3. 端口解析 ---
got=$(parse_ports "80, 443")
eq "ports comma" "$got" "80,443"
ec=0; parse_ports "0" >/dev/null 2>&1 || ec=$?
eq "port zero" "$ec" "1"
ec=0; parse_ports "65536" >/dev/null 2>&1 || ec=$?
eq "port big" "$ec" "1"
ec=0; parse_ports "0443" >/dev/null 2>&1 || ec=$?
eq "port pad" "$ec" "1"
seq_ports=""
i=1
while [ "$i" -le 31 ]; do
  seq_ports="${seq_ports:+$seq_ports,}$i"
  i=$((i + 1))
done
ec=0; parse_ports "$seq_ports" >/dev/null 2>&1 || ec=$?
eq "port cap" "$ec" "2"
eq "ports ideographic" "$(parse_ports '80，443、8080')" "80,443,8080"

# --- 4. 排除重叠检测 ---
tmp=$(mktemp -d "${TMPDIR:-/tmp}/fengjin-test.XXXXXX")
printf '%s\n' "1.2.3.9" "2001:db8::5" >"$tmp/peers"
printf '%s\n' \
  "ip4	1.2.3.9" \
  "net4	1.2.3.0/24" \
  "ip4	8.8.8.8" \
  "net4	9.9.9.0/24" \
  "net6	2001:db8::/32" \
  "ip6	2001:db8::9" \
  "ip6	2001:db9::5" \
  "domain	example.com" \
  | fengjin_awk overlap peers="$tmp/peers" skipfile="$tmp/skip" | LC_ALL=C sort >"$tmp/kept"
eq "overlap kept" "$(cat "$tmp/kept")" "$(printf '%s\n' 'domain	example.com' 'ip4	8.8.8.8' 'ip6	2001:db8::9' 'ip6	2001:db9::5' 'net4	9.9.9.0/24')"
eq "overlap skip6" "$(awk -F '\t' '$1 == "2001:db8::/32" { print $1 }' "$tmp/skip")" "2001:db8::/32"

# --- 5. 防火墙规则生成（含 VPS_FENGJIN_DNS 独立子链优化） ---
mkdir -p "$tmp/plan"
printf '%s\n' all >"$tmp/plan/mode"
printf '%s\n' "" >"$tmp/plan/ports"
printf '%s\n' "1.2.3.4" "10.1.0.0/24" >"$tmp/plan/v4"
printf '%s\n' "2001:db8::1" >"$tmp/plan/v6"
printf '%s\n' string >"$tmp/plan/dns.method"
printf '%s\n' example.com >"$tmp/plan/dns.list"
rules() {
  fengjin_awk rules plan="$tmp/plan" fam="$1" multiport="$2" algo="$3" icase=1 rtcp=reset roth=reject useset="$4" cap=1500
}
rules 4 1 bm 1 >"$tmp/r4"
eq "rule set tcp" "$(grep -c -- '-m set --match-set vps_fengjin4 dst -p tcp -j REJECT --reject-with tcp-reset' "$tmp/r4")" "1"
eq "rule set other" "$(grep -c -- '-m set --match-set vps_fengjin4 dst -j REJECT$' "$tmp/r4")" "1"
eq "rule dns jump" "$(grep -c -- '-A VPS_FENGJIN -p udp --dport 53 -j VPS_FENGJIN_DNS' "$tmp/r4")" "1"
eq "rule dns jump tcp" "$(grep -c -- '-A VPS_FENGJIN -p tcp --dport 53 -j VPS_FENGJIN_DNS' "$tmp/r4")" "1"
eq "rule dns subchain" "$(grep -c -- '^-A VPS_FENGJIN_DNS .*|076578616d706c6503636f6d00|' "$tmp/r4")" "2"
eq "rule dns icase" "$(grep -c -- '--algo bm --icase' "$tmp/r4")" "2"
eq "rule chains valid" "$(grep -Evc '^-A (VPS_FENGJIN|VPS_FENGJIN_DNS) ' "$tmp/r4" || true)" "0"
eq "rule no zero" "$(grep -c '0.0.0.0/0' "$tmp/r4" || true)" "0"
rules 4 1 "" 1 >"$tmp/r4a"
eq "rule no string support" "$(grep -c 'string' "$tmp/r4a" || true)" "0"
eq "rule no dns jump" "$(grep -c 'VPS_FENGJIN_DNS' "$tmp/r4a" || true)" "0"
rules 6 1 bm 1 >"$tmp/r6"
eq "rule set6" "$(grep -c -- 'vps_fengjin6' "$tmp/r6")" "2"

printf '%s\n' ports >"$tmp/plan/mode"
printf '%s\n' "80,443" >"$tmp/plan/ports"
printf '%s\n' none >"$tmp/plan/dns.method"
rules 4 1 bm 1 >"$tmp/rp"
eq "port dports" "$(grep -c -- '--dports 80,443' "$tmp/rp")" "2"
eq "port no dns" "$(grep -c 'dport 53' "$tmp/rp" || true)" "0"
printf '%s\n' string >"$tmp/plan/dns.method"
rules 4 1 bm 1 >"$tmp/rps"
eq "port string dns" "$(grep -c 'dport 53' "$tmp/rps")" "2"
eq "port string dns hex" "$(grep -c -- '|076578616d706c6503636f6d00|' "$tmp/rps")" "2"
printf '%s\n' none >"$tmp/plan/dns.method"

rules 4 0 bm 0 >"$tmp/rd"
eq "no ipset uses dest" "$(grep -c -- '-d 1.2.3.4' "$tmp/rd")" "4"
eq "split ports" "$(grep -c -- '--dport 443' "$tmp/rd")" "4"
eq "no multiport" "$(grep -c multiport "$tmp/rd" || true)" "0"
fengjin_awk rules plan="$tmp/plan" fam=4 multiport=1 useset=0 cap=1 >"$tmp/rcap"
eq "no ipset cap" "$(grep -c -- '-d 10.1.0.0/24' "$tmp/rcap" || true)" "0"

# --- 6. ipset 与 nft ---
fengjin_awk ipset plan="$tmp/plan" fam=4 setname=vps_fengjin4 >"$tmp/set4"
eq "ipset temp" "$(grep -c '^create vps_fengjin4_n hash:net family inet ' "$tmp/set4")" "1"
eq "ipset add" "$(grep -c '^add vps_fengjin4_n 1.2.3.4 -exist$' "$tmp/set4")" "1"
eq "ipset cidr" "$(grep -c '^add vps_fengjin4_n 10.1.0.0/24 -exist$' "$tmp/set4")" "1"
: >"$tmp/plan/v6"
ec=0
fengjin_awk ipset plan="$tmp/plan" fam=6 setname=vps_fengjin6 >/dev/null || ec=$?
eq "ipset empty" "$ec" "1"
printf '%s\n' "2001:db8::1" >"$tmp/plan/v6"

fengjin_awk nft plan="$tmp/plan" >"$tmp/nftp"
eq "nft ports tcp" "$(grep -c 'ip daddr @block4 tcp dport { 80, 443 } reject with tcp reset' "$tmp/nftp")" "1"
printf '%s\n' all >"$tmp/plan/mode"
fengjin_awk nft plan="$tmp/plan" >"$tmp/nft"
eq "nft hook" "$(grep -c 'hook output' "$tmp/nft")" "1"
eq "nft v4" "$(grep -c '1.2.3.4' "$tmp/nft")" "1"
eq "nft v6" "$(grep -c 'ip6 daddr @block6' "$tmp/nft")" "2"
eq "nft automerge" "$(grep -c 'auto-merge' "$tmp/nft")" "2"
eq "nft no forward" "$(grep -c 'hook forward' "$tmp/nft" || true)" "0"
fengjin_awk nft plan="$tmp/plan" nft_reject=0 nft_automerge=0 >"$tmp/nft_drop"
eq "nft drop fallback" "$(grep -c 'ip daddr @block4 drop' "$tmp/nft_drop")" "1"
eq "nft no automerge" "$(grep -c 'auto-merge' "$tmp/nft_drop" || true)" "0"

# --- 7. 目标匹配引擎（vps-fengjin test 核心） ---
eq "match exact domain" "$(fengjin_awk match plan="$tmp/plan" target='Example.com')" "domain_exact	example.com"
eq "match sub domain" "$(fengjin_awk match plan="$tmp/plan" target='https://api.sub.example.com/foo')" "domain_sub	example.com"
eq "match miss domain" "$(fengjin_awk match plan="$tmp/plan" target='notexample.com')" "none	notexample.com"
eq "match ipv4 exact" "$(fengjin_awk match plan="$tmp/plan" target='1.2.3.4')" "v4	1.2.3.4"
eq "match ipv4 cidr" "$(fengjin_awk match plan="$tmp/plan" target='10.1.0.88')" "v4	10.1.0.0/24"
eq "match ipv4 miss" "$(fengjin_awk match plan="$tmp/plan" target='8.8.8.8')" "none	8.8.8.8"
eq "match ipv6" "$(fengjin_awk match plan="$tmp/plan" target='2001:DB8::1')" "v6	2001:db8::1"
eq "match invalid" "$(fengjin_awk match plan="$tmp/plan" target='not a target')" "invalid	not a target"

# --- 8. rebuild_ips 与 DNS 策略选择 ---
mkdir -p "$tmp/cfg" "$tmp/work"
CFG="$tmp/cfg"
WORKDIR="$tmp/work"
SSH_CONNECTION=
SSH_CLIENT=
printf '%s\n' all >"$CFG/mode"
printf '%s\n' "" >"$CFG/ports"
printf '%s\n' "domain	example.com" "suffix	ads.example.net" "ip4	192.0.2.9" "net4	198.51.100.0/24" "ip6	2001:db8::1" >"$CFG/list.txt"
FW_BACKEND=iptables
OS_ID=debian
PM=none
V4_STRING=0
rebuild_ips
eq "rebuild v4 only explicit" "$(cat "$CFG/v4")" "$(printf '%s\n' 192.0.2.9 198.51.100.0/24)"
eq "rebuild v6 only explicit" "$(cat "$CFG/v6")" "2001:db8::1"
eq "rebuild dns list" "$(cat "$CFG/dns.list")" "$(printf '%s\n' ads.example.net example.com)"
if command -v dnsmasq >/dev/null 2>&1; then want_m=dnsmasq; else want_m=hosts; fi
eq "rebuild dns method no-pm" "$(cat "$CFG/dns.method")" "$want_m"
# 有包管理器但无 xt_string（例如 nftables 机器）：应选 dnsmasq 支持子域名，不再退化为 hosts！
FW_BACKEND=nft
PM=apt
eq "choose nft prefers dnsmasq" "$(choose_dns_method 10)" "dnsmasq"
FW_BACKEND=iptables
V4_STRING=1
eq "choose string small" "$(choose_dns_method 50)" "string"
eq "choose dnsmasq large" "$(choose_dns_method 500)" "dnsmasq"
FW_BACKEND=none
eq "choose none prefers dnsmasq" "$(choose_dns_method 5)" "dnsmasq"
rebuild_ips
eq "rebuild none v4 empty" "$(cat "$CFG/v4")" ""
eq "rebuild none v6 empty" "$(cat "$CFG/v6")" ""
eq "rebuild none dns list" "$(cat "$CFG/dns.list")" "$(printf '%s\n' ads.example.net example.com)"

# --- 9. 更换整套名单回归测试（确认不再混入旧名单！） ---
mkdir -p "$CFG/sources/1" "$WORKDIR/sources/2"
printf '%s\n' "domain	old.example.com" >"$CFG/sources/1/list"
printf '%s\n' "domain	new.example.com" >"$WORKDIR/sources/2/list"
PENDING="$WORKDIR/sources"
merge_sources pending "$WORKDIR/m_new"
eq "replace merges only pending" "$(cat "$WORKDIR/m_new")" "domain	new.example.com"
merge_sources all "$WORKDIR/m_all"
eq "append merges all" "$(cat "$WORKDIR/m_all")" "$(printf '%s\n' 'domain	new.example.com' 'domain	old.example.com')"

# --- 10. 交互流程端到端模拟（直接输入域名、批量粘贴不误截 FRONTEND、从第2步返回保留已加名单） ---
(
  CFG="$tmp/cfg_ui"
  WORKDIR="$tmp/work_ui"
  mkdir -p "$CFG" "$WORKDIR"
  PENDING="$WORKDIR/sources"
  mkdir -p "$PENDING"
  INPUT_READY=0
  STDIN_SAVED=0
  # 模拟小白：直接敲 "baidu.com, qq.com" -> 选 2 继续添加 -> 选 1 粘贴含 FRONTEND 的域名 -> 输入 完成 -> 选 1 下一步
  printf '%s\n' \
    'baidu.com, qq.com' \
    '2' \
    '1' \
    'DOMAIN,FRONTEND.example.com' \
    '1.2.3.4' \
    '完成' \
    '1' \
    | {
        exec 3<&0
        INPUT_READY=1
        IN_TTY=0
        wizard_add_sources "测试添加向导" keep >/dev/null 2>&1
        rc=$?
        merge_sources pending "$WORKDIR/out.list"
        printf '%s\n' "$rc" >"$WORKDIR/rc"
      }
)
eq "wizard exit ok" "$(cat "$tmp/work_ui/rc")" "0"
eq "wizard parsed items" "$(cat "$tmp/work_ui/out.list")" "$(printf '%s\n' 'domain	baidu.com' 'domain	frontend.example.com' 'domain	qq.com' 'ip4	1.2.3.4')"

# 源码检查：绝不碰 FORWARD 链、保留一键安装标记
if grep -q FORWARD install.sh; then
  printf 'FAIL source contains FORWARD\n' >&2
  fail=$((fail + 1))
else
  printf 'ok no FORWARD\n'
fi
if head -n 2 install.sh | grep -q 'vps-fengjin-onekey-begin'; then
  printf 'ok onekey marker present\n'
else
  printf 'FAIL missing onekey marker\n' >&2
  fail=$((fail + 1))
fi

rm -rf "$tmp"
if [ "$fail" -eq 0 ]; then
  printf 'all tests passed\n'
  exit 0
fi
printf '%s failed\n' "$fail" >&2
exit 1
