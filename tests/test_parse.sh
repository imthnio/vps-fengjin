#!/bin/sh
# 纯逻辑测试。不需要 root，也不改防火墙。
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

eq "domain" "$(classify 'Example.COM')" "domain	example.com"
eq "suffix star" "$(classify '*.Example.COM')" "suffix	example.com"
eq "suffix dot" "$(classify '.example.com')" "suffix	example.com"
eq "ipv4" "$(classify '1.2.3.4')" "ip4	1.2.3.4"
eq "cidr normalize" "$(classify '1.2.3.5/24')" "net4	1.2.3.0/24"
eq "cidr20" "$(classify '172.16.5.9/20')" "net4	172.16.0.0/20"
eq "wide v4" "$(classify '1.2.3.0/8')" "bad	wide	1.2.3.0/8"
eq "wide zero" "$(classify '0.0.0.0/0')" "bad	wide	0.0.0.0/0"
eq "local v4" "$(classify '127.0.0.1')" "bad	local	127.0.0.1"
eq "comment" "$(classify '# hello')" ""
eq "hosts" "$(classify '0.0.0.0 example.com foo.com')" "$(printf '%s\n' 'domain	example.com' 'domain	foo.com')"
eq "adblock" "$(classify '||Example.com^')" "suffix	example.com"
eq "clash suffix" "$(classify 'DOMAIN-SUFFIX,Example.com,PROXY')" "suffix	example.com"
eq "clash domain" "$(classify 'DOMAIN,www.example.com')" "domain	www.example.com"
eq "clash cidr" "$(classify 'IP-CIDR,10.1.2.0/24,no-resolve')" "net4	10.1.2.0/24"
eq "clash cidr6" "$(classify 'IP-CIDR6,2001:db8::/32')" "net6	2001:db8::/32"
eq "url" "$(classify 'https://www.Example.com/a/b')" "domain	www.example.com"
eq "dnsmasq" "$(classify 'address=/example.com/0.0.0.0')" "suffix	example.com"
eq "keyword" "$(classify 'DOMAIN-KEYWORD,abc')" "bad	keyword	DOMAIN-KEYWORD,abc"
eq "junk" "$(classify 'not a domain')" "bad	parse	not a domain"
eq "ipv6" "$(classify '2001:DB8::1')" "ip6	2001:db8::1"
eq "local v6" "$(classify '::1')" "bad	local	::1"
eq "wide v6" "$(classify '2001:db8::/16')" "bad	wide	2001:db8::/16"
eq "link local" "$(classify 'fe80::1')" "bad	local	fe80::1"
eq "cidr6 normalize" "$(classify '2001:db8:1234::5/32')" "net6	2001:db8::/32"
eq "cidr6 nibble" "$(classify '2001:db8:abcd:ef12::/50')" "net6	2001:db8:abcd:c000::/50"
eq "cidr6 keep" "$(classify '2400:cb00:1:2::/64')" "net6	2400:cb00:1:2::/64"
eq "numeric tld" "$(classify '0.0.0.0 0.0.0.0')" "bad	parse	0.0.0.0"
eq "hosts localhost" "$(classify '127.0.0.1 localhost')" "bad	parse	localhost"
eq "wire" "$(printf '%s\n' example.com | fengjin_awk wire)" "076578616d706c6503636f6d"

got=$(parse_ports "80, 443")
eq "ports comma" "$got" "80,443"
ec=0
parse_ports "0" >/dev/null 2>&1 || ec=$?
eq "port zero" "$ec" "1"
ec=0
parse_ports "65536" >/dev/null 2>&1 || ec=$?
eq "port big" "$ec" "1"
ec=0
parse_ports "0443" >/dev/null 2>&1 || ec=$?
eq "port pad" "$ec" "1"
seq_ports=""
i=1
while [ "$i" -le 31 ]; do
  if [ -n "$seq_ports" ]; then
    seq_ports="$seq_ports,$i"
  else
    seq_ports=$i
  fi
  i=$((i + 1))
done
ec=0
parse_ports "$seq_ports" >/dev/null 2>&1 || ec=$?
eq "port cap" "$ec" "2"
got=$(parse_ports "80，443")
eq "ports ideographic" "$got" "80,443"

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
  | fengjin_awk overlap "$tmp/peers" "" "$tmp/skip" | LC_ALL=C sort >"$tmp/kept"
eq "overlap kept" "$(cat "$tmp/kept")" "$(printf '%s\n' 'domain	example.com' 'ip4	8.8.8.8' 'ip6	2001:db8::9' 'ip6	2001:db9::5' 'net4	9.9.9.0/24')"
eq "overlap skip6" "$(awk -F '\t' '$1 == "2001:db8::/32" { print $1 }' "$tmp/skip")" "2001:db8::/32"

printf '%s\n' \
  "Server: 1.1.1.1" \
  "Address: 1.1.1.1#53" \
  "" \
  "Name: example.com" \
  "Address: 93.184.216.34" \
  "example.net." \
  | fengjin_awk extract "" "1.1.1.1" >"$tmp/ips"
eq "extract" "$(cat "$tmp/ips")" "93.184.216.34"

mkdir -p "$tmp/plan"
printf '%s\n' all >"$tmp/plan/mode"
printf '%s\n' "" >"$tmp/plan/ports"
printf '%s\n' "1.2.3.4" "10.1.0.0/24" >"$tmp/plan/v4"
printf '%s\n' "2001:db8::1" >"$tmp/plan/v6"
printf '%s\n' string >"$tmp/plan/dns.method"
printf '%s\n' example.com >"$tmp/plan/dns.list"
fengjin_awk rules "" "" "" "$tmp/plan" 4 1 bm reset reject 1 >"$tmp/r4"
eq "rule set" "$(grep -c -- '-m set --match-set vps_fengjin4 dst -j REJECT' "$tmp/r4")" "1"
eq "rule dns" "$(grep -c -- '076578616d706c6503636f6d' "$tmp/r4")" "2"
eq "rule dns end" "$(grep -c -- '|076578616d706c6503636f6d00|' "$tmp/r4")" "2"
eq "rule no zero" "$(grep -c '0.0.0.0/0' "$tmp/r4" || true)" "0"

printf '%s\n' ports >"$tmp/plan/mode"
printf '%s\n' "80,443" >"$tmp/plan/ports"
printf '%s\n' none >"$tmp/plan/dns.method"
fengjin_awk rules "" "" "" "$tmp/plan" 4 1 bm reset reject 1 >"$tmp/rp"
eq "port dports" "$(grep -c -- '--dports 80,443' "$tmp/rp")" "2"
eq "port no dns" "$(grep -c 'dport 53' "$tmp/rp" || true)" "0"

fengjin_awk rules "" "" "" "$tmp/plan" 4 0 bm reset reject 0 >"$tmp/rd"
eq "no ipset uses dest" "$(grep -c -- '-d 1.2.3.4' "$tmp/rd")" "4"
eq "split ports" "$(grep -c -- '--dport 443' "$tmp/rd")" "4"
eq "no multiport" "$(grep -c multiport "$tmp/rd" || true)" "0"

fengjin_awk ipset "" "" "" "$tmp/plan" 4 >"$tmp/set4"
eq "ipset add" "$(grep -c 'add vps_fengjin4 1.2.3.4' "$tmp/set4")" "1"
eq "ipset cidr" "$(grep -c 'add vps_fengjin4 10.1.0.0/24' "$tmp/set4")" "1"

printf '%s\n' all >"$tmp/plan/mode"
fengjin_awk nft "" "" "" "$tmp/plan" >"$tmp/nft"
eq "nft hook" "$(grep -c 'hook output' "$tmp/nft")" "1"
eq "nft v4" "$(grep -c '1.2.3.4' "$tmp/nft")" "1"
eq "nft no forward" "$(grep -c 'hook forward' "$tmp/nft" || true)" "0"

if grep -q FORWARD install.sh; then
  printf 'FAIL source contains FORWARD\n' >&2
  fail=$((fail + 1))
else
  printf 'ok no FORWARD\n'
fi

rm -rf "$tmp"
if [ "$fail" -eq 0 ]; then
  printf 'all tests passed\n'
  exit 0
fi
printf '%s failed\n' "$fail" >&2
exit 1
