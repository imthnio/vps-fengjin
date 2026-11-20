#!/bin/sh
# vps-fengjin-onekey-begin
#======================================================================
# VPS 出口封禁工具（vps-fengjin）
#
# 让这台服务器（含上面搭建的代理节点）无法访问指定的网站域名、IP 或网段。
# 第一次运行：2 步向导（添加名单 → 核对生效），全程大白话，小白也能轻松上手。
# 之后再运行：进入管理菜单（添加/查看/更新/删除名单、测试是否封住、暂停/开启、卸载）。
#
# 也支持命令行参数直接执行（适合自动化或批量部署）：
#   sh install.sh                          首次向导 / 管理菜单
#   sh install.sh -l 名单网址或文件 -y        全局封禁，不提问
#   sh install.sh -l 名单 -p 80,443 -y      仅封指定目标端口，不提问
#   vps-fengjin status                     查看状态与规则健康度
#   vps-fengjin test 域名或IP               测试某个网站或 IP 是否已被封住
#   vps-fengjin update-lists               重新下载所有在线链接名单并生效
#   vps-fengjin refresh                    按已存名单重新生效（定时巡检用）
#   vps-fengjin apply-rules                开机恢复规则（开机自启用）
#   vps-fengjin on | off                   开启 / 暂停封禁（保留名单）
#   vps-fengjin purge                      彻底卸载
#   vps-fengjin check 文件或网址            只检查名单内容，不改防火墙
#
# 64MB 内存小鸡也能跑：不装大软件，临时文件放硬盘。
# 域名只在 DNS 解析层拦截（含子域名），不封解析出来的 IP，不会误伤同 IP 的其他网站；
# 名单里直接写的 IP / 网段走防火墙拦截。
#======================================================================

VERSION=3.0.0
CFG=/etc/vps-fengjin
CHAIN=VPS_FENGJIN
DNS_CHAIN=VPS_FENGJIN_DNS
SET4=vps_fengjin4
SET6=vps_fengjin6
NFT_TABLE=vpsfengjin
BIN_DEFAULT=/usr/local/sbin/vps-fengjin
BIN_LINK=/usr/local/bin/vps-fengjin

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

if [ -t 1 ]; then
  C_RED=$(printf '\033[0;31m')
  C_GREEN=$(printf '\033[0;32m')
  C_YELLOW=$(printf '\033[1;33m')
  C_BLUE=$(printf '\033[0;34m')
  C_CYAN=$(printf '\033[1;36m')
  C_BOLD=$(printf '\033[1m')
  C_DIM=$(printf '\033[2m')
  C_NC=$(printf '\033[0m')
else
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_CYAN=''
  C_BOLD=''
  C_DIM=''
  C_NC=''
fi

say()      { printf '%s\n' "$*"; }
say_ok()   { printf '%s\n' "${C_GREEN}✓ $*${C_NC}"; }
say_info() { printf '%s\n' "${C_BLUE}ℹ $*${C_NC}"; }
say_warn() { printf '%s\n' "${C_YELLOW}! $*${C_NC}"; }
say_err()  { printf '%s\n' "${C_RED}✗ $*${C_NC}" >&2; }
say_dim()  { printf '%s\n' "${C_DIM}$*${C_NC}"; }
say_step() {
  printf '\n%s\n' "${C_DIM}────────────────────────────────────────────${C_NC}"
  printf '%s\n' "${C_CYAN}  $*${C_NC}"
  printf '%s\n' "${C_DIM}────────────────────────────────────────────${C_NC}"
}
ui_hr()    { printf '%s\n' "${C_DIM}────────────────────────────────────────────${C_NC}"; }
ui_banner() {
  printf '\n%s\n' "${C_CYAN}============================================${C_NC}"
  printf '%s\n' "${C_BOLD}  VPS 出口封禁工具 (vps-fengjin)  v${VERSION}${C_NC}"
  printf '%s\n' "${C_CYAN}============================================${C_NC}"
}
die()      { say_err "$*"; exit 1; }

# 统计文件里的非空行数，文件不存在算 0。
count_lines() {
  if [ -f "$1" ]; then
    awk 'NF { c++ } END { print c + 0 }' "$1"
  else
    printf '%s\n' 0
  fi
}

#----------------------------------------------------------------------
# 纯逻辑引擎（AWK）。测试可直接调用，不改系统。
#   fengjin_awk 模式 [变量=值 ...]
# 模式：classify / ports / wire / overlap / match / rules / ipset / nft
#----------------------------------------------------------------------

FENGJIN_AWK='
function trim(s) {
  sub(/\r$/, "", s)
  gsub(/^[ \t]+/, "", s)
  gsub(/[ \t]+$/, "", s)
  return s
}
function bad(code, s) {
  gsub(/\t/, " ", s)
  if (length(s) > 120) s = substr(s, 1, 120)
  print "bad\t" code "\t" s
}
function is_ipv4(s,   a, i, n) {
  if (s !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
  n = split(s, a, ".")
  if (n != 4) return 0
  for (i = 1; i <= 4; i++) {
    if (length(a[i]) > 1 && substr(a[i], 1, 1) == "0") return 0
    if ((a[i] + 0) > 255) return 0
  }
  return 1
}
function v4_special(ip,   a, o1, o2) {
  split(ip, a, ".")
  o1 = a[1] + 0
  o2 = a[2] + 0
  if (o1 == 0 || o1 == 127 || o1 >= 224) return 1
  if (o1 == 169 && o2 == 254) return 1
  return 0
}
function ip4num(s,   a) {
  split(s, a, ".")
  return a[1] * 16777216 + a[2] * 65536 + a[3] * 256 + a[4]
}
function v4_network(ip, bits,   n, shift, net) {
  n = ip4num(ip)
  if ((bits + 0) <= 0) return "0.0.0.0"
  shift = 2 ^ (32 - bits)
  net = int(n / shift) * shift
  return (int(net / 16777216) % 256) "." (int(net / 65536) % 256) "." (int(net / 256) % 256) "." (int(net) % 256)
}
function v4_contains(net, ip,   a, base, bits, shift) {
  if (index(net, "/") > 0) {
    if (split(net, a, "/") != 2) return 0
    base = a[1]
    bits = a[2] + 0
  } else {
    base = net
    bits = 32
  }
  if (!is_ipv4(base) || !is_ipv4(ip)) return 0
  if (bits < 0 || bits > 32) return 0
  if (bits == 0) return 1
  shift = 2 ^ (32 - bits)
  return int(ip4num(base) / shift) == int(ip4num(ip) / shift)
}
function v6group_ok(g) {
  return length(g) >= 1 && length(g) <= 4 && g ~ /^[0-9A-Fa-f]+$/
}
function is_ipv6(s,   n, i, parts, lc, rc, lg, rg) {
  if (s == "") return 0
  if (s ~ /[^0-9A-Fa-f:]/) return 0
  n = split(s, parts, "::")
  if (n > 2) return 0
  if (index(s, "::") == 0) {
    n = split(s, lg, ":")
    if (n != 8) return 0
    for (i = 1; i <= n; i++) if (!v6group_ok(lg[i])) return 0
    return 1
  }
  lc = 0
  rc = 0
  if (parts[1] != "") {
    lc = split(parts[1], lg, ":")
    for (i = 1; i <= lc; i++) if (!v6group_ok(lg[i])) return 0
  }
  if (parts[2] != "") {
    rc = split(parts[2], rg, ":")
    for (i = 1; i <= rc; i++) if (!v6group_ok(rg[i])) return 0
  }
  return lc + rc <= 7
}
function pad4(h) {
  h = tolower(h)
  while (length(h) < 4) h = "0" h
  return h
}
function v6_expand(s,   n, i, parts, lc, rc, lg, rg, zeros, out) {
  if (!is_ipv6(s)) return ""
  out = ""
  if (index(s, "::") == 0) {
    n = split(s, lg, ":")
    for (i = 1; i <= n; i++) out = out pad4(lg[i])
    return length(out) == 32 ? out : ""
  }
  split(s, parts, "::")
  lc = 0
  rc = 0
  if (parts[1] != "") lc = split(parts[1], lg, ":")
  if (parts[2] != "") rc = split(parts[2], rg, ":")
  zeros = 8 - lc - rc
  if (zeros < 0) return ""
  for (i = 1; i <= lc; i++) out = out pad4(lg[i])
  for (i = 1; i <= zeros; i++) out = out "0000"
  for (i = 1; i <= rc; i++) out = out pad4(rg[i])
  return length(out) == 32 ? out : ""
}
function hexval(c) {
  c = tolower(c)
  if (c >= "0" && c <= "9") return c + 0
  return index("abcdef", c) > 0 ? 9 + index("abcdef", c) : -1
}
function v6_contains(net, ip,   a, base, bits, eb, ei, full, rem, sh, nb, ni) {
  if (index(net, "/") > 0) {
    if (split(net, a, "/") != 2) return 0
    base = a[1]
    bits = a[2] + 0
  } else {
    base = net
    bits = 128
  }
  eb = v6_expand(base)
  ei = v6_expand(ip)
  if (eb == "" || ei == "") return 0
  if (bits < 0 || bits > 128) return 0
  full = int(bits / 4)
  rem = bits % 4
  if (substr(eb, 1, full) != substr(ei, 1, full)) return 0
  if (rem == 0) return 1
  nb = hexval(substr(eb, full + 1, 1))
  ni = hexval(substr(ei, full + 1, 1))
  sh = 2 ^ (4 - rem)
  return int(nb / sh) == int(ni / sh)
}
function v6_network(s, bits,   e, full, rem, out, nb, sh, i, g, best, bestlen, run, start, text) {
  e = v6_expand(s)
  if (e == "") return ""
  full = int(bits / 4)
  rem = bits % 4
  out = substr(e, 1, full)
  if (rem > 0) {
    nb = hexval(substr(e, full + 1, 1))
    sh = 2 ^ (4 - rem)
    out = out sprintf("%x", int(nb / sh) * sh)
  }
  while (length(out) < 32) out = out "0"
  best = 0
  bestlen = 0
  run = 0
  for (i = 1; i <= 8; i++) {
    g[i] = substr(out, i * 4 - 3, 4)
    sub(/^0+/, "", g[i])
    if (g[i] == "") g[i] = "0"
    if (g[i] == "0") {
      if (run == 0) start = i
      run++
      if (run > bestlen) { best = start; bestlen = run }
    } else run = 0
  }
  if (bestlen < 2) best = 0
  text = ""
  for (i = 1; i <= 8; i++) {
    if (best > 0 && i >= best && i < best + bestlen) {
      if (i == best) text = text "::"
      continue
    }
    if (text != "" && text !~ /::$/) text = text ":"
    text = text g[i]
  }
  return text
}
function v6_special(s,   e) {
  e = v6_expand(s)
  if (e == "") return 1
  if (e ~ /^0+$/ || e ~ /^0+1$/) return 1
  if (e ~ /^ff/ || e ~ /^fe[89ab]/) return 1
  return 0
}
function is_domain(s,   n, i, lab) {
  if (length(s) < 3 || length(s) > 253) return 0
  if (s !~ /^[A-Za-z0-9.-]+$/) return 0
  if (s ~ /\.\./ || s ~ /\.$/ || s ~ /^\./) return 0
  n = split(s, lab, ".")
  if (n < 2) return 0
  for (i = 1; i <= n; i++) {
    if (length(lab[i]) < 1 || length(lab[i]) > 63) return 0
    if (lab[i] !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) return 0
  }
  return lab[n] !~ /^[0-9]+$/
}
function is_sink(s) {
  return s == "0.0.0.0" || s == "127.0.0.1" || s == "::" || s == "::1" || s == "255.255.255.255"
}
function is_hosts_boilerplate(s) {
  s = tolower(s)
  return s == "localhost" || s == "localhost.localdomain" || s == "local" \
    || s == "broadcasthost" || s == "ip6-localhost" || s == "ip6-loopback" \
    || s == "ip6-localnet" || s == "ip6-mcastprefix" || s == "ip6-allnodes" \
    || s == "ip6-allrouters" || s == "ip6-allhosts"
}
function emit_name(kind, host) {
  host = tolower(trim(host))
  sub(/\.$/, "", host)
  if (substr(host, 1, 2) == "*." || substr(host, 1, 2) == "+.") {
    kind = "suffix"
    host = substr(host, 3)
  } else if (substr(host, 1, 1) == ".") {
    kind = "suffix"
    host = substr(host, 2)
  }
  if (is_ipv4(host) || is_ipv6(host)) {
    emit_addr(host)
    return
  }
  if (!is_domain(host)) {
    bad("parse", host)
    return
  }
  print kind "\t" host
}
function emit_addr(s,   a, left, bits, net) {
  s = trim(s)
  if (index(s, "/") > 0) {
    if (split(s, a, "/") != 2) { bad("parse", s); return }
    left = a[1]
    bits = a[2]
    if (is_ipv4(left)) {
      if (bits !~ /^[0-9]+$/ || (bits + 0) > 32) { bad("parse", s); return }
      if ((bits + 0) < 16) { bad("wide", s); return }
      net = v4_network(left, bits + 0)
      if (v4_special(net)) { bad("local", s); return }
      print "net4\t" net "/" (bits + 0)
      return
    }
    if (is_ipv6(left)) {
      if (bits !~ /^[0-9]+$/ || (bits + 0) > 128) { bad("parse", s); return }
      if ((bits + 0) < 32) { bad("wide", s); return }
      left = tolower(left)
      if (v6_special(left)) { bad("local", s); return }
      net = v6_network(left, bits + 0)
      if (v6_special(net)) { bad("local", s); return }
      print "net6\t" net "/" (bits + 0)
      return
    }
    bad("parse", s)
    return
  }
  if (is_ipv4(s)) {
    if (v4_special(s)) { bad("local", s); return }
    print "ip4\t" s
    return
  }
  if (is_ipv6(s)) {
    s = tolower(s)
    if (v6_special(s)) { bad("local", s); return }
    print "ip6\t" s
    return
  }
  bad("parse", s)
}
function strip_url(s) {
  if (s ~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\//) {
    sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", s)
    if (s ~ /^[^\/ \t]+@/) sub(/^[^@]+@/, "", s)
    sub(/[\/?#].*$/, "", s)
  }
  return s
}
# 判断单个词像不像一个合法目标（用于支持小白在一行里用逗号/空格输入多个网站或 IP）
function looks_like_target(t,   h, a) {
  t = trim(t)
  if (t == "") return 0
  t = strip_url(t)
  if (substr(t, 1, 1) == "[" && match(t, /^\[[0-9A-Fa-f:]+\]/)) {
    return is_ipv6(substr(t, 2, RLENGTH - 2))
  }
  if (t ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", t)
  if (is_ipv4(t) || is_ipv6(t)) return 1
  if (index(t, "/") > 0) {
    split(t, a, "/")
    if (is_ipv4(a[1]) || is_ipv6(a[1])) return (split(t, a, "/") == 2 && a[2] ~ /^[0-9]+$/)
    h = a[1]
    sub(/:[0-9]+$/, "", h)
    return is_domain(tolower(h))
  }
  h = tolower(t)
  if (substr(h, 1, 2) == "*." || substr(h, 1, 2) == "+.") h = substr(h, 3)
  else if (substr(h, 1, 1) == ".") h = substr(h, 2)
  sub(/\.$/, "", h)
  if (h ~ /:[0-9]+$/) sub(/:[0-9]+$/, "", h)
  return is_domain(h)
}
function emit_single_target(s,   a, host) {
  s = strip_url(trim(s))
  if (substr(s, 1, 1) == "[" && match(s, /^\[[0-9A-Fa-f:]+\]/)) {
    emit_addr(substr(s, 2, RLENGTH - 2))
    return
  }
  if (s ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", s)
  if (is_ipv4(s) || is_ipv6(s)) {
    emit_addr(s)
    return
  }
  if (index(s, "/") > 0) {
    split(s, a, "/")
    if (is_ipv4(a[1]) || is_ipv6(a[1])) {
      emit_addr(s)
      return
    }
    # 像 www.baidu.com/s?wd=123 这种没带 https:// 的网址，提取前面的域名。
    host = a[1]
    sub(/:[0-9]+$/, "", host)
    if (is_domain(tolower(host))) {
      emit_name("domain", host)
      return
    }
    emit_addr(s)
    return
  }
  if (s ~ /:[0-9]+$/ && index(s, "]") == 0) {
    host = s
    sub(/:[0-9]+$/, "", host)
    if (is_domain(tolower(host))) {
      emit_name("domain", host)
      return
    }
  }
  emit_name("domain", s)
}
function emit_addr_or_name(s,   n, f, i, all_ok, t) {
  n = split(s, f, /[ \t]+/)
  if (n >= 2 && is_sink(f[1])) {
    for (i = 2; i <= n; i++) {
      if (is_hosts_boilerplate(f[i]) || is_sink(f[i])) continue
      emit_name("domain", f[i])
    }
    return
  }
  if (n >= 2) {
    # 小白用空格隔开写多个网站/IP 时，只有每个词都合法才拆分，避免把英文句子误认。
    all_ok = 1
    for (i = 1; i <= n; i++) {
      if (!looks_like_target(f[i])) { all_ok = 0; break }
    }
    if (all_ok) {
      for (i = 1; i <= n; i++) emit_single_target(f[i])
      return
    }
    bad("parse", s)
    return
  }
  emit_single_target(s)
}
function do_classify(   s, f, kind, host, n, i, all_ok, t) {
  s = $0
  sub(/^\357\273\277/, "", s)
  s = trim(s)
  if (s == "" || substr(s, 1, 1) == "#" || substr(s, 1, 1) == "!" || substr(s, 1, 1) == ";") return
  if (substr(s, 1, 2) == "@@" || substr(s, 1, 2) == "//") return
  sub(/[ \t]+#.*/, "", s)
  s = trim(s)
  if (s == "") return
  # Clash YAML 名单：payload: 与 - 规则
  if (s ~ /^payload:[ \t]*$/) return
  if (s ~ /^-[ \t]+/) {
    sub(/^-[ \t]+/, "", s)
    s = trim(s)
  }
  if (length(s) >= 2 && ((substr(s, 1, 1) == "\047" && substr(s, length(s), 1) == "\047") \
      || (substr(s, 1, 1) == "\"" && substr(s, length(s), 1) == "\""))) {
    s = trim(substr(s, 2, length(s) - 2))
  }
  if (s == "") return
  # 全角逗号、顿号统一转成英文逗号（LC_ALL=C 下不能放进 [...] 字符类，必须按完整字节串替换）
  gsub(/[ \t]*，[ \t]*/, ",", s)
  gsub(/[ \t]*、[ \t]*/, ",", s)
  # dnsmasq 格式：address=/example.com/0.0.0.0
  if (s ~ /^address=\//) {
    split(s, f, "/")
    emit_name("suffix", f[2])
    return
  }
  # AdBlock / AdGuard 格式：||example.com^
  if (s ~ /^\|\|/) {
    sub(/^\|\|/, "", s)
    sub(/\^.*$/, "", s)
    emit_name("suffix", s)
    return
  }
  # v2fly / geosite 格式：full:example.com / domain:example.com
  if (s ~ /^(full|domain|keyword|regexp):/) {
    sub(/[ \t]+@.*$/, "", s)
    if (s ~ /^full:/) { emit_name("domain", substr(s, 6)); return }
    if (s ~ /^domain:/) { emit_name("suffix", substr(s, 8)); return }
    if (s ~ /^keyword:/) { bad("keyword", s); return }
    bad("unsupported", s)
    return
  }
  # 逗号分隔：先识别 Clash/Surge 规则，再支持小白用逗号写多个域名/IP
  if (index(s, ",") > 0) {
    n = split(s, f, ",")
    kind = toupper(trim(f[1]))
    host = trim(f[2])
    if (kind == "DOMAIN" || kind == "HOST") { emit_name("domain", host); return }
    if (kind == "DOMAIN-SUFFIX" || kind == "HOST-SUFFIX") { emit_name("suffix", host); return }
    if (kind == "DOMAIN-KEYWORD") {
      if (index(host, ".") > 0) emit_name("suffix", host)
      else bad("keyword", s)
      return
    }
    if (kind == "IP-CIDR" || kind == "IP-CIDR6") { emit_addr(host); return }
    if (kind ~ /^[A-Z][A-Z0-9_-]*$/) { bad("unsupported", s); return }
    all_ok = 1
    for (i = 1; i <= n; i++) {
      t = trim(f[i])
      if (t == "") continue
      if (!looks_like_target(t)) { all_ok = 0; break }
    }
    if (all_ok) {
      for (i = 1; i <= n; i++) {
        t = trim(f[i])
        if (t != "") emit_single_target(t)
      }
      return
    }
  }
  emit_addr_or_name(s)
}
function do_ports(   n, i, p, c, a, arr, j, t, out) {
  gsub(/，/, ",", $0)
  gsub(/、/, ",", $0)
  n = split($0, a, /[ \t,]+/)
  c = 0
  for (i = 1; i <= n; i++) {
    p = a[i]
    if (p == "") continue
    if (p !~ /^[0-9]+$/ || (p + 0) < 1 || (p + 0) > 65535) exit 1
    if (length(p) > 1 && substr(p, 1, 1) == "0") exit 1
    if (seen[p + 0]++) continue
    arr[++c] = p + 0
  }
  if (c == 0) exit 1
  if (c > 30) exit 2
  for (i = 1; i <= c; i++) {
    for (j = i + 1; j <= c; j++) {
      if (arr[j] < arr[i]) { t = arr[i]; arr[i] = arr[j]; arr[j] = t }
    }
  }
  out = arr[1]
  for (i = 2; i <= c; i++) out = out "," arr[i]
  print out
}
function wire_hex(s,   n, i, j, L, out, ch, labels) {
  s = tolower(trim(s))
  sub(/\.$/, "", s)
  if (s == "") return ""
  n = split(s, labels, ".")
  out = ""
  for (i = 1; i <= n; i++) {
    L = length(labels[i])
    if (L < 1 || L > 63) return ""
    out = out sprintf("%02x", L)
    for (j = 1; j <= L; j++) {
      ch = substr(labels[i], j, 1)
      if (!(ch in ord)) return ""
      out = out sprintf("%02x", ord[ch])
    }
  }
  return out
}
function do_wire(   h) {
  h = wire_hex($0)
  if (h != "" && length(h) <= 240) print h
}
function note_skip(msg) {
  if (skipfile != "") print msg >> skipfile
}
function do_overlap(   n, x, kind, val, i) {
  n = split($0, x, "\t")
  if (n < 2) return
  kind = x[1]
  val = x[2]
  if (kind == "ip4" || kind == "net4") {
    for (i = 1; i <= npeers4; i++) {
      if (v4_contains(val, p4[i])) { note_skip(val "\t" p4[i]); return }
    }
  } else if (kind == "ip6" || kind == "net6") {
    for (i = 1; i <= npeers6; i++) {
      if (v6_contains(val, p6[i])) { note_skip(val "\t" p6[i]); return }
    }
  }
  print kind "\t" val
}
function do_match(   t, line, n, parts, i, j, cand, dset) {
  t = trim(target)
  t = strip_url(t)
  if (substr(t, 1, 1) == "[" && match(t, /^\[[0-9A-Fa-f:]+\]/)) {
    t = substr(t, 2, RLENGTH - 2)
  }
  if (t ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", t)
  if (index(t, "/") > 0 && !is_ipv4(substr(t, 1, index(t, "/") - 1)) && !is_ipv6(substr(t, 1, index(t, "/") - 1))) {
    sub(/\/.*$/, "", t)
  }
  if (is_ipv4(t)) {
    while ((getline line < (plan "/v4")) > 0) {
      if (line != "" && v4_contains(line, t)) { print "v4\t" line; close(plan "/v4"); return }
    }
    close(plan "/v4")
    print "none\t" t
    return
  }
  if (is_ipv6(t)) {
    t = tolower(t)
    while ((getline line < (plan "/v6")) > 0) {
      if (line != "" && v6_contains(line, t)) { print "v6\t" line; close(plan "/v6"); return }
    }
    close(plan "/v6")
    print "none\t" t
    return
  }
  if (t ~ /:[0-9]+$/) sub(/:[0-9]+$/, "", t)
  t = tolower(t)
  sub(/^\*\./, "", t)
  sub(/^\+\./, "", t)
  sub(/^\./, "", t)
  sub(/\.$/, "", t)
  if (!is_domain(t)) { print "invalid\t" target; return }
  while ((getline line < (plan "/dns.list")) > 0) {
    if (line != "") dset[line] = 1
  }
  close(plan "/dns.list")
  if (t in dset) { print "domain_exact\t" t; return }
  n = split(t, parts, ".")
  for (i = 2; i <= n - 1; i++) {
    cand = parts[i]
    for (j = i + 1; j <= n; j++) cand = cand "." parts[j]
    if (cand in dset) { print "domain_sub\t" cand; return }
  }
  print "none\t" t
}
function read_one(path,   line) {
  line = ""
  if ((getline line < path) <= 0) line = ""
  close(path)
  return line
}
function has_lines(path,   line, r) {
  r = 0
  while ((getline line < path) > 0) if (line != "") { r = 1; break }
  close(path)
  return r
}
function tcp_jump() {
  return rtcp == "reset" ? "REJECT --reject-with tcp-reset" : (roth == "reject" ? "REJECT" : "DROP")
}
function oth_jump() {
  return roth == "reject" ? "REJECT" : "DROP"
}
function rule(spec) {
  print "-A " chain " " spec
}
function dns_rule(spec) {
  print "-A " dnschain " " spec
}
function emit_match(mspec, mode_s, ports_s,   n, i, p, group, count) {
  if (mode_s == "all") {
    rule(mspec " -p tcp -j " tcp_jump())
    rule(mspec " -j " oth_jump())
    return
  }
  if (ports_s == "") return
  n = split(ports_s, p, ",")
  if (multiport == "1") {
    group = ""
    count = 0
    for (i = 1; i <= n; i++) {
      group = group (group == "" ? "" : ",") p[i]
      if (++count == 15 || i == n) {
        rule(mspec " -p tcp -m multiport --dports " group " -j " tcp_jump())
        rule(mspec " -p udp -m multiport --dports " group " -j " oth_jump())
        group = ""
        count = 0
      }
    }
    return
  }
  for (i = 1; i <= n; i++) {
    rule(mspec " -p tcp --dport " p[i] " -j " tcp_jump())
    rule(mspec " -p udp --dport " p[i] " -j " oth_jump())
  }
}
function render_rules(   mode_s, ports_s, method, list, setname, addr, line, h, c, opt, has_dns) {
  mode_s = read_one(plan "/mode")
  ports_s = read_one(plan "/ports")
  method = read_one(plan "/dns.method")
  list = plan "/v" fam
  setname = fam == "6" ? set6 : set4
  if (useset == "1") {
    if (has_lines(list)) emit_match("-m set --match-set " setname " dst", mode_s, ports_s)
  } else {
    c = 0
    while ((getline addr < list) > 0) {
      if (addr == "") continue
      if (++c > cap) break
      emit_match("-d " addr, mode_s, ports_s)
    }
    close(list)
  }
  if (method != "string" || algo == "") return
  # 仅对 53 端口 DNS 流量跳转到独立子链，普通代理流量（如 443）不遍历域名规则，几乎零性能开销。
  opt = " --algo " algo (icase == "1" ? " --icase" : "")
  has_dns = 0
  while ((getline line < (plan "/dns.list")) > 0) {
    h = wire_hex(line)
    if (h == "" || length(h) > 240) continue
    if (!has_dns) {
      rule("-p udp --dport 53 -j " dnschain)
      rule("-p tcp --dport 53 -j " dnschain)
      has_dns = 1
    }
    dns_rule("-p udp -m string --hex-string |" h "00|" opt " -j " oth_jump())
    dns_rule("-p tcp -m string --hex-string |" h "00|" opt " -j " tcp_jump())
  }
  close(plan "/dns.list")
}
function render_ipset(   list, family, n, line, maxe, hs, tmp) {
  list = plan "/v" fam
  family = fam == "6" ? "inet6" : "inet"
  tmp = setname "_n"
  n = 0
  while ((getline line < list) > 0) if (line != "") n++
  close(list)
  if (n == 0) exit 1
  maxe = n + 1024
  if (maxe < 65536) maxe = 65536
  hs = 1024
  if (n > 4000) hs = 4096
  if (n > 50000) hs = 16384
  print "create " tmp " hash:net family " family " hashsize " hs " maxelem " maxe
  while ((getline line < list) > 0) if (line != "") print "add " tmp " " line " -exist"
  close(list)
}
function nft_set(name, type, path,   line, first) {
  print "  set " name " {"
  print "    type " type
  print "    flags interval"
  if (nft_automerge == "1") print "    auto-merge"
  print "    elements = {"
  first = 1
  while ((getline line < path) > 0) {
    if (line == "") continue
    printf "%s      %s", (first ? "" : ",\n"), line
    first = 0
  }
  close(path)
  print ""
  print "    }"
  print "  }"
}
function nft_rules(target,   ports) {
  if (mode_s == "all") {
    if (nft_reject == "1") {
      print "    " target " meta l4proto tcp reject with tcp reset"
      print "    " target " reject"
    } else {
      print "    " target " drop"
    }
    return
  }
  if (ports_s == "") return
  ports = ports_s
  gsub(/,/, ", ", ports)
  if (nft_reject == "1") {
    print "    " target " tcp dport { " ports " } reject with tcp reset"
    print "    " target " udp dport { " ports " } reject"
  } else {
    print "    " target " tcp dport { " ports " } drop"
    print "    " target " udp dport { " ports " } drop"
  }
}
function render_nft(   h4, h6) {
  mode_s = read_one(plan "/mode")
  ports_s = read_one(plan "/ports")
  h4 = has_lines(plan "/v4")
  h6 = has_lines(plan "/v6")
  print "table inet " table " {"
  if (h4) nft_set("block4", "ipv4_addr", plan "/v4")
  if (h6) nft_set("block6", "ipv6_addr", plan "/v6")
  print "  chain out {"
  print "    type filter hook output priority -50; policy accept;"
  if (h4) nft_rules("ip daddr @block4")
  if (h6) nft_rules("ip6 daddr @block6")
  print "  }"
  print "}"
}
BEGIN {
  for (i = 1; i < 128; i++) ord[sprintf("%c", i)] = i
  if (chain == "") chain = "VPS_FENGJIN"
  if (dnschain == "") dnschain = "VPS_FENGJIN_DNS"
  if (set4 == "") set4 = "vps_fengjin4"
  if (set6 == "") set6 = "vps_fengjin6"
  if (table == "") table = "vpsfengjin"
  if (cap == "") cap = 1500
  if (nft_reject == "") nft_reject = "1"
  if (nft_automerge == "") nft_automerge = "1"
  if (mode == "rules") { render_rules(); exit }
  if (mode == "ipset") { render_ipset(); exit }
  if (mode == "nft") { render_nft(); exit }
  if (mode == "match") { do_match(); exit }
  if (mode == "overlap" && peers != "") {
    while ((getline line < peers) > 0) {
      line = trim(line)
      if (is_ipv4(line)) p4[++npeers4] = line
      else if (is_ipv6(line)) p6[++npeers6] = line
    }
    close(peers)
  }
}
{
  if (mode == "classify") do_classify()
  else if (mode == "ports") do_ports()
  else if (mode == "wire") do_wire()
  else if (mode == "overlap") do_overlap()
}
'

fengjin_awk() {
  _fa_mode=$1
  shift
  _fa_n=$#
  for _fa_arg in "$@"; do
    set -- "$@" -v "$_fa_arg"
  done
  shift "$_fa_n"
  LC_ALL=C awk -v mode="$_fa_mode" "$@" "$FENGJIN_AWK"
}

# 返回 0 时输出整理好的端口；1 表示格式错，2 表示超过 30 个。
parse_ports() {
  printf '%s\n' "$1" | fengjin_awk ports
}

# GitHub 网页链接自动转 Raw 直链。
normalize_url() {
  _nu_u=$1
  case $_nu_u in
    https://github.com/*/blob/*|http://github.com/*/blob/*)
      _nu_rest=${_nu_u#*github.com/}
      _nu_owner=${_nu_rest%%/*}; _nu_rest=${_nu_rest#*/}
      _nu_repo=${_nu_rest%%/*}; _nu_rest=${_nu_rest#*/}
      _nu_rest=${_nu_rest#blob/}
      _nu_rest=${_nu_rest%%\?*}
      if [ -n "$_nu_owner" ] && [ -n "$_nu_repo" ] && [ -n "$_nu_rest" ]; then
        printf 'https://raw.githubusercontent.com/%s/%s/%s\n' "$_nu_owner" "$_nu_repo" "$_nu_rest"
        return 0
      fi
      ;;
    https://github.com/*/raw/*|http://github.com/*/raw/*)
      _nu_rest=${_nu_u#*github.com/}
      _nu_owner=${_nu_rest%%/*}; _nu_rest=${_nu_rest#*/}
      _nu_repo=${_nu_rest%%/*}; _nu_rest=${_nu_rest#*/}
      _nu_rest=${_nu_rest#raw/}
      _nu_rest=${_nu_rest%%\?*}
      if [ -n "$_nu_owner" ] && [ -n "$_nu_repo" ] && [ -n "$_nu_rest" ]; then
        printf 'https://raw.githubusercontent.com/%s/%s/%s\n' "$_nu_owner" "$_nu_repo" "$_nu_rest"
        return 0
      fi
      ;;
  esac
  printf '%s\n' "$_nu_u"
}

#----------------------------------------------------------------------
# 交互输入封装（所有回答走 fd 3，提示语走 stderr，不污染 $(...)）
#----------------------------------------------------------------------

save_stdin() {
  [ "${STDIN_SAVED:-0}" = 1 ] && return 0
  STDIN_SAVED=1
  exec 4<&0
}

input_init() {
  [ "${INPUT_READY:-0}" = 1 ] && return 0
  INPUT_READY=1
  save_stdin
  IN_TTY=0
  if [ -t 4 ]; then
    exec 3<&4
    IN_TTY=1
  elif (exec 3</dev/tty) 2>/dev/null; then
    exec 3</dev/tty
    IN_TTY=1
  else
    exec 3<&4
  fi
}

# ask 提示 [默认值]。结果放在 ANSWER。
ask() {
  input_init
  printf '%s' "$1" >&2
  if ! IFS= read -r ANSWER <&3; then
    printf '\n' >&2
    die "输入已中断。若想直接用参数自动运行，示例：vps-fengjin -l 名单网址 -y"
  fi
  [ "$IN_TTY" = 1 ] || printf '%s\n' "$ANSWER" >&2
  ANSWER=$(printf '%s' "$ANSWER" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -n "$ANSWER" ] || ANSWER=${2:-}
}

# ask_yn 提示 默认(y/n)。是返回 0，否返回 1。
ask_yn() {
  while :; do
    ask "$1" "$2"
    case $ANSWER in
      y|Y|yes|Yes|YES|是|好|确定|确认) return 0 ;;
      n|N|no|No|NO|否|不|取消) return 1 ;;
    esac
    say_warn "请输入 y（确认）或 n（取消）。"
  done
}

# ask_pick 提示 默认 可选值...
ask_pick() {
  _ap_prompt=$1
  _ap_def=$2
  shift 2
  while :; do
    ask "$_ap_prompt" "$_ap_def"
    for _ap_c in "$@"; do
      [ "$ANSWER" = "$_ap_c" ] && return 0
    done
    say_warn "请输入选项编号：$(printf '%s ' "$@" | sed 's/ $//;s/ / \/ /g')。"
  done
}

# 交互终端下暂停，让用户看清结果再刷回菜单。
pause_enter() {
  input_init
  [ "$IN_TTY" = 1 ] || return 0
  printf '\n%s' "${C_DIM}按回车键继续...${C_NC}" >&2
  IFS= read -r _pe_dummy <&3 || true
}

#----------------------------------------------------------------------
# 系统、内存、交换空间、软件源
#----------------------------------------------------------------------

detect_os() {
  PM=none
  for _pm in apt-get dnf yum apk pacman zypper opkg; do
    if command -v "$_pm" >/dev/null 2>&1; then
      PM=$_pm
      break
    fi
  done
  [ "$PM" = apt-get ] && PM=apt
  OS_ID=unknown
  OS_PRETTY=""
  if [ -r /etc/os-release ]; then
    OS_ID=$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')
    OS_PRETTY=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | tr -d '"')
  fi
  if [ -r /etc/openwrt_release ]; then
    PM=opkg
    OS_ID=openwrt
    [ -n "$OS_PRETTY" ] || OS_PRETTY=OpenWrt
  fi
  [ -n "$OS_PRETTY" ] || OS_PRETTY=$OS_ID
}

mem_total_kb() {
  _kb=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null)
  case ${_kb:-} in
    ''|*[!0-9]*) printf '%s\n' 0 ;;
    *) printf '%s\n' "$_kb" ;;
  esac
}

list_limits() {
  LIST_MAX_MB=32
  LIST_MAX_BYTES=$((LIST_MAX_MB * 1048576))
  if [ "$(mem_total_kb)" -gt 196608 ]; then
    LIST_MAX_ITEMS=500000
  else
    LIST_MAX_ITEMS=100000
  fi
}

no_ipset_rule_cap() {
  _kb=$(mem_total_kb)
  if [ "$_kb" -eq 0 ] || [ "$_kb" -le 131072 ]; then
    printf '%s\n' 1500
  elif [ "$_kb" -le 524288 ]; then
    printf '%s\n' 4000
  else
    printf '%s\n' 8000
  fi
}

pick_tmpdir() {
  for _d in "${TMPDIR:-}" /var/tmp /root /tmp; do
    [ -n "$_d" ] && [ -d "$_d" ] && [ -w "$_d" ] || continue
    _fs=$(df -P "$_d" 2>/dev/null | awk 'NR == 2 { print $1 }')
    case $_fs in
      tmpfs|ramfs|none) [ "$_d" = /tmp ] || continue ;;
    esac
    printf '%s\n' "$_d"
    return 0
  done
  printf '%s\n' /tmp
}

lowmem_prepare() {
  _kb=$(mem_total_kb)
  [ "$_kb" -gt 0 ] && [ "$_kb" -le 196608 ] || return 0
  say_info "检测到小内存机器（约 $((_kb / 1024)) MB），自动优化内存策略..."
  sysctl -w vm.overcommit_memory=1 >/dev/null 2>&1 || true
  if awk 'NR > 1 { found = 1 } END { exit found ? 0 : 1 }' /proc/swaps 2>/dev/null; then
    return 0
  fi
  _free=$(df -Pk / 2>/dev/null | awk 'NR == 2 { print $4 }')
  case ${_free:-} in
    ''|*[!0-9]*) _free=0 ;;
  esac
  if [ "$_free" -ge 180000 ]; then
    make_swap || say_warn "未能开启交换空间（受限容器里常见），将继续运行。"
  fi
}

make_swap() {
  _f=/swapfile-vps-fengjin
  if [ -f "$_f" ]; then
    grep -q "$_f" /proc/swaps 2>/dev/null && return 0
    swapon "$_f" 2>/dev/null && return 0
    rm -f "$_f"
  fi
  # 用 dd 分配连续块，避免部分文件系统上 fallocate 建出的文件 swapon 失败。
  if ! dd if=/dev/zero of="$_f" bs=1048576 count=64 >/dev/null 2>&1; then
    rm -f "$_f"
    return 1
  fi
  if ! chmod 600 "$_f" || ! mkswap "$_f" >/dev/null 2>&1 || ! swapon "$_f" 2>/dev/null; then
    rm -f "$_f"
    return 1
  fi
  if ! grep -q "$_f" /etc/fstab 2>/dev/null; then
    printf '%s none swap sw 0 0\n' "$_f" >>/etc/fstab
  fi
  say_ok "已自动增加 64MB 交换空间"
}

pm_install() {
  _pm_log=${WORKDIR:-/tmp}/pm.log
  case ${PM:-none} in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      if [ "${APT_UPDATED:-0}" != 1 ]; then
        apt-get update -qq >>"$_pm_log" 2>&1 || say_warn "软件源更新未完全成功，仍尝试继续安装。"
        APT_UPDATED=1
      fi
      apt-get install -y -qq --no-install-recommends \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        "$1" >>"$_pm_log" 2>&1
      ;;
    apk) apk add --no-cache "$1" >>"$_pm_log" 2>&1 ;;
    dnf) dnf install -y -q "$1" >>"$_pm_log" 2>&1 ;;
    yum) yum install -y -q "$1" >>"$_pm_log" 2>&1 ;;
    pacman) pacman -Sy --noconfirm "$1" >>"$_pm_log" 2>&1 ;;
    zypper) zypper --non-interactive -q install "$1" >>"$_pm_log" 2>&1 ;;
    opkg)
      if [ "${OPKG_UPDATED:-0}" != 1 ]; then
        opkg update >>"$_pm_log" 2>&1 || say_warn "opkg 源更新失败，仍尝试继续安装。"
        OPKG_UPDATED=1
      fi
      opkg install "$1" >>"$_pm_log" 2>&1
      ;;
    *) return 1 ;;
  esac
}

need_cmd() {
  _nc_cmd=$1
  shift
  command -v "$_nc_cmd" >/dev/null 2>&1 && return 0
  [ "${PM:-none}" != none ] || return 1
  for _nc_pkg in "$@"; do
    say_dim "  正在自动安装依赖：$_nc_pkg ..."
    : >"${WORKDIR:-/tmp}/pm.log"
    if pm_install "$_nc_pkg" && command -v "$_nc_cmd" >/dev/null 2>&1; then
      return 0
    fi
  done
  say_warn "依赖 $_nc_cmd 自动安装失败。"
  if [ -s "${WORKDIR:-/tmp}/pm.log" ]; then
    tail -n 3 "${WORKDIR:-/tmp}/pm.log" 2>/dev/null | sed 's/^/    /'
  fi
  return 1
}

#----------------------------------------------------------------------
# 防火墙探测与写入（仅控制本机出站 OUTPUT，含代理节点转发出去的连接）
#----------------------------------------------------------------------

ipt_try() {
  _it_bin=$1
  shift
  "$_it_bin" -A VPS_FENGJIN_T "$@" >/dev/null 2>&1
  _it_rc=$?
  "$_it_bin" -F VPS_FENGJIN_T >/dev/null 2>&1
  return $_it_rc
}

ipt_candidates() {
  if [ "$1" = 6 ]; then
    printf '%s\n' ip6tables ip6tables-legacy ip6tables-nft
  else
    printf '%s\n' iptables iptables-legacy iptables-nft
  fi
}

probe_ipt_family() {
  _pf_fam=inet
  [ "$1" = 6 ] && _pf_fam=inet6
  P_OK=0
  P_BIN=""
  P_REJECT=0
  P_RESET=0
  P_MULTI=0
  P_SET=0
  P_STRING=0
  P_ALGO=bm
  P_ICASE=0
  for _pf_bin in $(ipt_candidates "$1"); do
    command -v "$_pf_bin" >/dev/null 2>&1 || continue
    "$_pf_bin" -F VPS_FENGJIN_T >/dev/null 2>&1
    "$_pf_bin" -X VPS_FENGJIN_T >/dev/null 2>&1
    if "$_pf_bin" -N VPS_FENGJIN_T >/dev/null 2>"$WORKDIR/ipt.err"; then
      P_BIN=$_pf_bin
      break
    fi
    [ "$1" = 4 ] && printf '%s：%s\n' "$_pf_bin" "$(head -n 1 "$WORKDIR/ipt.err")" >>"$WORKDIR/fw.err"
  done
  [ -n "$P_BIN" ] || return 0
  P_OK=1
  ipt_try "$P_BIN" -j REJECT && P_REJECT=1
  ipt_try "$P_BIN" -p tcp -j REJECT --reject-with tcp-reset && P_RESET=1
  ipt_try "$P_BIN" -p tcp -m multiport --dports 80,443 -j RETURN && P_MULTI=1
  if command -v ipset >/dev/null 2>&1; then
    ipset destroy vps_fengjin_t >/dev/null 2>&1
    if ipset create vps_fengjin_t hash:net family "$_pf_fam" maxelem 16 >/dev/null 2>&1; then
      ipt_try "$P_BIN" -m set --match-set vps_fengjin_t dst -j RETURN && P_SET=1
      ipset destroy vps_fengjin_t >/dev/null 2>&1
    fi
  fi
  for _pf_algo in bm kmp; do
    if ipt_try "$P_BIN" -p udp --dport 53 -m string --hex-string "|61|" --algo "$_pf_algo" -j RETURN; then
      P_STRING=1
      P_ALGO=$_pf_algo
      ipt_try "$P_BIN" -p udp --dport 53 -m string --hex-string "|61|" --algo "$_pf_algo" --icase -j RETURN && P_ICASE=1
      break
    fi
  done
  "$P_BIN" -X VPS_FENGJIN_T >/dev/null 2>&1
}

# 真正探测 nft 建表、挂 output 钩子、auto-merge 与 reject 能力。
probe_nft() {
  NFT_REJECT=0
  NFT_AUTOMERGE=0
  command -v nft >/dev/null 2>&1 || return 1
  nft delete table inet vpsfengjin_t >/dev/null 2>&1
  nft delete table inet vpsfengjin_t2 >/dev/null 2>&1
  if ! nft -f - >/dev/null 2>"$WORKDIR/nft.err" <<'EOF'
table inet vpsfengjin_t {
  set s4 {
    type ipv4_addr
    flags interval
    elements = { 192.0.2.1 }
  }
  chain out {
    type filter hook output priority -50; policy accept;
    ip daddr @s4 drop
  }
}
EOF
  then
    printf 'nft：%s\n' "$(head -n 1 "$WORKDIR/nft.err")" >>"$WORKDIR/fw.err"
    return 1
  fi
  if nft -f - >/dev/null 2>&1 <<'EOF'
table inet vpsfengjin_t2 {
  set s4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 192.0.2.1, 192.0.2.0/24 }
  }
}
EOF
  then
    NFT_AUTOMERGE=1
    nft delete table inet vpsfengjin_t2 >/dev/null 2>&1
  fi
  if nft add rule inet vpsfengjin_t out ip daddr @s4 meta l4proto tcp reject with tcp reset >/dev/null 2>&1 \
    && nft add rule inet vpsfengjin_t out ip daddr @s4 reject >/dev/null 2>&1; then
    NFT_REJECT=1
  fi
  nft delete table inet vpsfengjin_t >/dev/null 2>&1
  return 0
}

has_net_admin() {
  _hn_cap=$(awk '/^CapEff:/ { print $2; exit }' /proc/self/status 2>/dev/null)
  [ -n "$_hn_cap" ] || return 0
  case $(printf '%s' "$_hn_cap" | awk '{ print substr($0, length($0) - 3, 1) }') in
    [13579bBdDfF]) return 0 ;;
  esac
  return 1
}

probe_firewall() {
  [ "${PROBED:-0}" = 1 ] && return 0
  PROBED=1
  : >"$WORKDIR/fw.err"
  FW_BACKEND=none
  NFT_REJECT=0
  NFT_AUTOMERGE=0
  for _fam in 4 6; do
    for _v in OK SET STRING MULTI REJECT RESET ICASE; do
      eval "V${_fam}_$_v=0"
    done
    eval "V${_fam}_BIN='' V${_fam}_ALGO=bm"
  done
  has_net_admin || return 0
  for _m in ip_tables iptable_filter ip6_tables ip6table_filter ip_set ip_set_hash_net \
    xt_set xt_string xt_multiport nf_tables nft_reject_inet; do
    modprobe "$_m" >/dev/null 2>&1
  done
  for _fam in 4 6; do
    probe_ipt_family "$_fam"
    for _v in OK BIN REJECT RESET MULTI SET STRING ALGO ICASE; do
      eval "V${_fam}_$_v=\$P_$_v"
    done
  done
  if [ "$V4_OK" = 1 ]; then
    FW_BACKEND=iptables
  elif probe_nft; then
    FW_BACKEND=nft
  fi
}

fw_precheck() {
  [ "${FW_CHECKED:-0}" = 1 ] && return 0
  FW_CHECKED=1
  PROBED=0
  if has_net_admin; then
    command -v iptables >/dev/null 2>&1 || need_cmd iptables iptables || true
    command -v ipset >/dev/null 2>&1 || need_cmd ipset ipset || true
    probe_firewall
    if [ "$V4_OK" != 1 ] && [ "${PM:-none}" = apk ] && ! command -v iptables-legacy >/dev/null 2>&1; then
      need_cmd iptables-legacy iptables-legacy || true
      PROBED=0
      probe_firewall
    fi
    if [ "$FW_BACKEND" = none ] && ! command -v nft >/dev/null 2>&1; then
      need_cmd nft nftables nft || true
      PROBED=0
      probe_firewall
    fi
  else
    probe_firewall
  fi
}

fw_summary_line() {
  case $FW_BACKEND in
    none)
      say_warn "环境受限：这台机器没有修改防火墙权限，已自动切换为「仅封禁域名」模式。"
      if ! has_net_admin; then
        say_dim "  说明：常见于 LXC/Docker 等受限容器（未开启 NET_ADMIN）。域名照常可封，IP/网段会跳过。"
      else
        say_dim "  说明：系统防火墙不可用，域名照常可封，IP/网段会跳过。"
      fi
      ;;
    nft)
      say_ok "环境就绪：域名与 IP/网段均可完整封禁（防火墙：nftables）"
      ;;
    *)
      if [ "$V4_SET" = 1 ]; then
        say_ok "环境就绪：域名与 IP/网段均可完整封禁（防火墙：$V4_BIN + ipset）"
      else
        say_ok "环境就绪：域名与 IP/网段均可封禁（防火墙：${V4_BIN}）"
        say_dim "  提示：当前机器不支持 ipset，IP/网段最多生效 $(no_ipset_rule_cap) 条，域名不受此限制。"
      fi
      ;;
  esac
}

ipv6_on() {
  [ -r /proc/net/if_inet6 ] || return 1
  [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = 1 ] && return 1
  return 0
}

remove_ipt_family() {
  for _rf_bin in $(ipt_candidates "$1"); do
    command -v "$_rf_bin" >/dev/null 2>&1 || continue
    while "$_rf_bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
      "$_rf_bin" -D OUTPUT -j "$CHAIN" >/dev/null 2>&1 || break
    done
    "$_rf_bin" -F "$CHAIN" >/dev/null 2>&1
    "$_rf_bin" -F "$DNS_CHAIN" >/dev/null 2>&1
    "$_rf_bin" -X "$DNS_CHAIN" >/dev/null 2>&1
    "$_rf_bin" -X "$CHAIN" >/dev/null 2>&1
  done
  return 0
}

remove_sets() {
  command -v ipset >/dev/null 2>&1 || return 0
  for _s in "$@"; do
    ipset destroy "$_s" >/dev/null 2>&1
    ipset destroy "${_s}_n" >/dev/null 2>&1
  done
  return 0
}

remove_nft() {
  command -v nft >/dev/null 2>&1 || return 0
  nft delete table inet "$NFT_TABLE" >/dev/null 2>&1
  return 0
}

remove_firewall() {
  remove_ipt_family 4
  remove_ipt_family 6
  remove_sets "$SET4" "$SET6"
  remove_nft
}

load_set() {
  if [ "$1" = 6 ]; then _ls_name=$SET6; else _ls_name=$SET4; fi
  [ -s "$CFG/v$1" ] || return 0
  ipset destroy "${_ls_name}_n" >/dev/null 2>&1
  fengjin_awk ipset plan="$CFG" fam="$1" setname="$_ls_name" >"$WORKDIR/set$1" || return 1
  if ! ipset restore <"$WORKDIR/set$1"; then
    ipset destroy "${_ls_name}_n" >/dev/null 2>&1
    say_err "IPv$1 地址集写入失败。"
    return 1
  fi
  if ! ipset swap "${_ls_name}_n" "$_ls_name" >/dev/null 2>&1; then
    ipset rename "${_ls_name}_n" "$_ls_name" >/dev/null 2>&1 || {
      ipset destroy "${_ls_name}_n" >/dev/null 2>&1
      say_err "IPv$1 地址集切换失败。"
      return 1
    }
  fi
  ipset destroy "${_ls_name}_n" >/dev/null 2>&1
  return 0
}

apply_ipt_family() {
  _af=$1
  eval "_af_bin=\$V${_af}_BIN _af_ok=\$V${_af}_OK _af_set=\$V${_af}_SET _af_multi=\$V${_af}_MULTI _af_rst=\$V${_af}_RESET"
  eval "_af_rej=\$V${_af}_REJECT _af_str=\$V${_af}_STRING _af_algo=\$V${_af}_ALGO _af_icase=\$V${_af}_ICASE"
  if [ "$_af_ok" != 1 ]; then
    remove_ipt_family "$_af"
    return 0
  fi
  _af_rtcp=drop
  [ "$_af_rst" = 1 ] && _af_rtcp=reset
  _af_roth=drop
  [ "$_af_rej" = 1 ] && _af_roth=reject
  [ "$_af_str" = 1 ] || _af_algo=""
  _af_rules=$WORKDIR/rules$_af
  fengjin_awk rules plan="$CFG" fam="$_af" multiport="$_af_multi" algo="$_af_algo" icase="$_af_icase" \
    rtcp="$_af_rtcp" roth="$_af_roth" useset="$_af_set" cap="$(no_ipset_rule_cap)" \
    chain="$CHAIN" dnschain="$DNS_CHAIN" set4="$SET4" set6="$SET6" >"$_af_rules"
  if [ ! -s "$_af_rules" ]; then
    remove_ipt_family "$_af"
    return 0
  fi
  _af_has_dns=0
  grep -q -- "-j $DNS_CHAIN" "$_af_rules" && _af_has_dns=1
  if command -v "$_af_bin-restore" >/dev/null 2>&1; then
    {
      printf '*filter\n:%s - [0:0]\n' "$CHAIN"
      [ "$_af_has_dns" = 1 ] && printf ':%s - [0:0]\n' "$DNS_CHAIN"
      cat "$_af_rules"
      printf 'COMMIT\n'
    } >"$_af_rules.restore"
    if ! "$_af_bin-restore" --noflush <"$_af_rules.restore"; then
      say_err "IPv$_af 防火墙规则写入失败，原规则保持不变。"
      return 1
    fi
    if [ "$_af_has_dns" = 0 ]; then
      "$_af_bin" -F "$DNS_CHAIN" >/dev/null 2>&1
      "$_af_bin" -X "$DNS_CHAIN" >/dev/null 2>&1
    fi
  else
    "$_af_bin" -N "$CHAIN" >/dev/null 2>&1
    "$_af_bin" -F "$CHAIN" >/dev/null 2>&1
    if [ "$_af_has_dns" = 1 ]; then
      "$_af_bin" -N "$DNS_CHAIN" >/dev/null 2>&1
      "$_af_bin" -F "$DNS_CHAIN" >/dev/null 2>&1
    else
      "$_af_bin" -F "$DNS_CHAIN" >/dev/null 2>&1
      "$_af_bin" -X "$DNS_CHAIN" >/dev/null 2>&1
    fi
    set -f
    while IFS= read -r _af_rule; do
      # shellcheck disable=SC2086
      if ! "$_af_bin" $_af_rule; then
        set +f
        "$_af_bin" -F "$CHAIN" >/dev/null 2>&1
        "$_af_bin" -F "$DNS_CHAIN" >/dev/null 2>&1
        say_err "防火墙规则写入失败：$_af_rule"
        return 1
      fi
    done <"$_af_rules"
    set +f
  fi
  if ! "$_af_bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
    "$_af_bin" -I OUTPUT 1 -j "$CHAIN" || return 1
  fi
  return 0
}

apply_firewall() {
  probe_firewall
  _fw_do6=0
  ipv6_on && _fw_do6=1
  case $FW_BACKEND in
    iptables)
      remove_nft
      if [ "$V4_SET" = 1 ]; then
        load_set 4 || return 1
      elif [ "$(count_lines "$CFG/v4")" -gt "$(no_ipset_rule_cap)" ]; then
        say_warn "当前无 ipset，IPv4 地址仅写入前 $(no_ipset_rule_cap) 条。"
      fi
      if [ "$_fw_do6" = 1 ]; then
        if [ "$V6_SET" = 1 ]; then
          load_set 6 || return 1
        elif [ "$(count_lines "$CFG/v6")" -gt "$(no_ipset_rule_cap)" ]; then
          say_warn "当前无 ipset，IPv6 地址仅写入前 $(no_ipset_rule_cap) 条。"
        fi
      fi
      apply_ipt_family 4 || return 1
      if [ -s "$WORKDIR/rules4" ]; then printf '%s\n' 1 >"$CFG/v4.active"; else printf '%s\n' 0 >"$CFG/v4.active"; fi
      if [ "$_fw_do6" = 1 ]; then
        apply_ipt_family 6 || return 1
        if [ "$V6_OK" = 1 ] && [ -s "$WORKDIR/rules6" ]; then
          printf '%s\n' 1 >"$CFG/v6.active"
        else
          printf '%s\n' 0 >"$CFG/v6.active"
        fi
      else
        remove_ipt_family 6
        printf '%s\n' 0 >"$CFG/v6.active"
      fi
      [ -s "$CFG/v4" ] && [ "$V4_SET" = 1 ] || remove_sets "$SET4"
      [ -s "$CFG/v6" ] && [ "$V6_SET" = 1 ] && [ "$_fw_do6" = 1 ] || remove_sets "$SET6"
      ;;
    nft)
      remove_ipt_family 4
      remove_ipt_family 6
      remove_sets "$SET4" "$SET6"
      {
        printf 'table inet %s\n' "$NFT_TABLE"
        printf 'delete table inet %s\n' "$NFT_TABLE"
        fengjin_awk nft plan="$CFG" table="$NFT_TABLE" \
          nft_reject="$NFT_REJECT" nft_automerge="$NFT_AUTOMERGE"
      } >"$WORKDIR/rules.nft"
      if ! nft -f "$WORKDIR/rules.nft"; then
        say_err "nftables 规则写入失败，原规则保持不变。"
        return 1
      fi
      ;;
    *)
      say_err "当前机器无法写入防火墙规则。"
      return 1
      ;;
  esac
  return 0
}

ipt_chain_live() {
  for _rl_bin in $(ipt_candidates "$1"); do
    command -v "$_rl_bin" >/dev/null 2>&1 || continue
    "$_rl_bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1 && return 0
  done
  return 1
}

rules_live() {
  case $(cat "$CFG/backend" 2>/dev/null) in
    none)
      dns_live
      ;;
    nft)
      nft list table inet "$NFT_TABLE" >/dev/null 2>&1
      ;;
    *)
      _rl_need4=$(cat "$CFG/v4.active" 2>/dev/null)
      _rl_need6=$(cat "$CFG/v6.active" 2>/dev/null)
      if [ -z "$_rl_need4" ] && [ -z "$_rl_need6" ]; then
        # 兼容旧版本升级前未写入 v4.active / v6.active 的情况
        _rl_method=$(cat "$CFG/dns.method" 2>/dev/null)
        if [ -s "$CFG/v4" ] || [ "$_rl_method" = string ]; then _rl_need4=1; fi
      fi
      if [ "$_rl_need4" = 1 ]; then
        ipt_chain_live 4 || return 1
      fi
      if [ "$_rl_need6" = 1 ]; then
        ipt_chain_live 6 || return 1
      fi
      return 0
      ;;
  esac
}

#----------------------------------------------------------------------
# 域名拦截（DNS 查询拦截 / dnsmasq / hosts）
#----------------------------------------------------------------------

dnsmasq_pids() {
  if command -v pidof >/dev/null 2>&1; then
    pidof dnsmasq 2>/dev/null
    return $?
  fi
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -x dnsmasq 2>/dev/null
    return $?
  fi
  _dp_found=""
  for _dp_p in /proc/[0-9]*/comm; do
    [ -r "$_dp_p" ] || continue
    if [ "$(cat "$_dp_p" 2>/dev/null)" = dnsmasq ]; then
      _dp_id=${_dp_p#/proc/}
      _dp_id=${_dp_id%/comm}
      _dp_found="$_dp_found $_dp_id"
    fi
  done
  [ -n "$_dp_found" ] || return 1
  printf '%s\n' "${_dp_found# }"
}

dnsmasq_up() {
  dnsmasq_pids >/dev/null 2>&1
}

dns_live() {
  case $(cat "$CFG/dns.method" 2>/dev/null) in
    dnsmasq)
      dnsmasq_up || return 1
      if [ -f "$CFG/dnsmasq.owned" ]; then
        grep -Eq '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.1([[:space:]]|$)' /etc/resolv.conf 2>/dev/null || return 1
      fi
      return 0
      ;;
    hosts)
      grep -q '^# BEGIN vps-fengjin$' /etc/hosts 2>/dev/null
      ;;
    *) return 0 ;;
  esac
}

flush_dns_cache() {
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl flush-caches >/dev/null 2>&1 || true
  elif command -v systemd-resolve >/dev/null 2>&1; then
    systemd-resolve --flush-caches >/dev/null 2>&1 || true
  fi
  if command -v nscd >/dev/null 2>&1 && [ -S /var/run/nscd/socket ]; then
    nscd -i hosts >/dev/null 2>&1 || true
  fi
}

strip_marked_file() {
  [ -f "$1" ] || return 0
  grep -q '^# BEGIN vps-fengjin$' "$1" 2>/dev/null || return 0
  awk '
    $0 == "# BEGIN vps-fengjin" { s = 1; next }
    $0 == "# END vps-fengjin" { s = 0; next }
    s != 1 { print }
  ' "$1" >"$WORKDIR/marked.new"
  cat "$WORKDIR/marked.new" >"$1"
}

hosts_clear() {
  strip_marked_file /etc/hosts
}

hosts_apply() {
  [ -s "$CFG/dns.list" ] || { hosts_clear; return 0; }
  _ha_n=$(count_lines "$CFG/dns.list")
  if [ "$_ha_n" -gt 2000 ]; then
    say_warn "/etc/hosts 模式仅写入前 2000 个域名，过多会拖慢系统。"
  fi
  {
    if [ -f /etc/hosts ]; then
      awk '
        $0 == "# BEGIN vps-fengjin" { s = 1; next }
        $0 == "# END vps-fengjin" { s = 0; next }
        s != 1 { print }
      ' /etc/hosts
    fi
    printf '%s\n' "# BEGIN vps-fengjin"
    head -n 2000 "$CFG/dns.list" | awk '
      NF { d = $1; seen[d] = 1; list[++n] = d }
      END {
        for (i = 1; i <= n; i++) {
          d = list[i]
          print "0.0.0.0 " d
          print ":: " d
          # 若未写 www.，顺带补上 www.，减少 /etc/hosts 漏拦主站的尴尬
          if (n <= 1000 && d !~ /^www\./ && !(("www." d) in seen)) {
            print "0.0.0.0 www." d
            print ":: www." d
          }
        }
      }
    '
    printf '%s\n' "# END vps-fengjin"
  } >"$WORKDIR/hosts.new"
  cmp -s "$WORKDIR/hosts.new" /etc/hosts 2>/dev/null && return 0
  if ! cat "$WORKDIR/hosts.new" 2>/dev/null >/etc/hosts; then
    say_err "/etc/hosts 为只读文件，无法写入域名规则。"
    return 1
  fi
}

kill_dnsmasq() {
  _kd_pids=$(dnsmasq_pids 2>/dev/null)
  [ -n "$_kd_pids" ] || return 0
  # shellcheck disable=SC2086
  kill $_kd_pids >/dev/null 2>&1
  sleep 1
}

dnsmasq_reads_confdir() {
  # Debian/Ubuntu 的 /etc/init.d/dnsmasq 自带 /etc/dnsmasq.d（即使 /etc/default/dnsmasq 里被注释），不可重复追加。
  if [ -f /etc/default/dnsmasq ] && grep -q '/etc/dnsmasq\.d' /etc/init.d/dnsmasq 2>/dev/null; then
    return 0
  fi
  grep -q '^CONFIG_DIR=/etc/dnsmasq\.d' /etc/default/dnsmasq 2>/dev/null && return 0
  grep -Eq '^[[:space:]]*conf-dir=/etc/dnsmasq\.d' /etc/dnsmasq.conf 2>/dev/null
}

restart_dnsmasq() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl enable dnsmasq >/dev/null 2>&1
    systemctl restart dnsmasq >/dev/null 2>&1
    sleep 1
    dnsmasq_up && return 0
  fi
  if [ -x /etc/init.d/dnsmasq ]; then
    /etc/init.d/dnsmasq restart >/dev/null 2>&1
    sleep 1
    dnsmasq_up && return 0
  fi
  kill_dnsmasq
  command -v dnsmasq >/dev/null 2>&1 || return 1
  if [ -f "$CFG/dnsmasq.owned" ] && [ -f /etc/dnsmasq.d/vps-fengjin.conf ]; then
    dnsmasq --conf-file=/etc/dnsmasq.d/vps-fengjin.conf >/dev/null 2>&1
  else
    dnsmasq >/dev/null 2>&1
  fi
  sleep 1
  dnsmasq_up
}

stop_dnsmasq() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now dnsmasq >/dev/null 2>&1
  fi
  if command -v rc-service >/dev/null 2>&1; then
    rc-service dnsmasq stop >/dev/null 2>&1
    rc-update del dnsmasq default >/dev/null 2>&1
  fi
  [ -x /etc/init.d/dnsmasq ] && /etc/init.d/dnsmasq stop >/dev/null 2>&1
  kill_dnsmasq
  return 0
}

dnsmasq_clear() {
  _dc_changed=0
  if [ -f /etc/dnsmasq.d/vps-fengjin.conf ]; then
    rm -f /etc/dnsmasq.d/vps-fengjin.conf
    _dc_changed=1
  fi
  if grep -q '^# BEGIN vps-fengjin$' /etc/dnsmasq.conf 2>/dev/null; then
    strip_marked_file /etc/dnsmasq.conf
    _dc_changed=1
  fi
  if [ -f "$CFG/dnsmasq.confdir" ] && [ -f /etc/dnsmasq.conf ]; then
    grep -vxF 'conf-dir=/etc/dnsmasq.d/,*.conf' /etc/dnsmasq.conf >"$WORKDIR/dnsmasq.conf.new"
    cat "$WORKDIR/dnsmasq.conf.new" >/etc/dnsmasq.conf
    rm -f "$CFG/dnsmasq.confdir"
    _dc_changed=1
  fi
  if grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null; then
    if [ -f "$CFG/resolv.conf.link" ]; then
      _dc_link=$(cat "$CFG/resolv.conf.link" 2>/dev/null)
      [ -n "$_dc_link" ] && ln -sf "$_dc_link" /etc/resolv.conf 2>/dev/null || true
      rm -f "$CFG/resolv.conf.link"
    elif [ -f "$CFG/resolv.conf.bak" ]; then
      cat "$CFG/resolv.conf.bak" >/etc/resolv.conf 2>/dev/null || true
    fi
  fi
  if [ -f "$CFG/dnsmasq.owned" ]; then
    stop_dnsmasq
    rm -f "$CFG/dnsmasq.owned"
  elif [ "$_dc_changed" = 1 ] && dnsmasq_up; then
    restart_dnsmasq || true
  fi
  if [ -f "$CFG/resolved.was_active" ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
      systemctl enable --now systemd-resolved >/dev/null 2>&1 || true
    fi
    rm -f "$CFG/resolved.was_active"
  fi
  return 0
}

write_dnsmasq_conf() {
  {
    if [ "$2" = 1 ]; then
      printf '%s\n' "listen-address=127.0.0.1" "bind-interfaces" "no-resolv" "no-hosts" \
        "cache-size=1000" "domain-needed"
      if [ -s "$CFG/upstream.dns" ]; then
        awk 'NF { print "server=" $1 }' "$CFG/upstream.dns"
      else
        printf '%s\n' "server=1.1.1.1" "server=8.8.8.8"
      fi
    fi
    awk 'NF { print "address=/" $1 "/" }' "$CFG/dns.list"
  } >"$1"
}

pick_probe_domain() {
  for _pd in iana.org icann.org example.org cloudflare.com; do
    grep -qxF "$_pd" "$CFG/dns.list" 2>/dev/null || { printf '%s\n' "$_pd"; return 0; }
  done
  printf '%s\n' iana.org
}

dnsmasq_apply() {
  [ -s "$CFG/dns.list" ] || return 0
  _dm_shared=0
  if [ ! -f "$CFG/dnsmasq.owned" ] && { [ "$OS_ID" = openwrt ] || dnsmasq_up; }; then
    _dm_shared=1
  fi
  if [ "$_dm_shared" = 0 ]; then
    pick_resolver
    case $RESOLVER in dig|host|nslookup|drill) ;; *) return 1 ;; esac
  fi
  mkdir -p /etc/dnsmasq.d 2>/dev/null
  [ -d /etc/dnsmasq.d ] || return 1
  write_dnsmasq_conf "$WORKDIR/dnsmasq.conf" "$((1 - _dm_shared))"
  _dm_changed=0
  if ! cmp -s "$WORKDIR/dnsmasq.conf" /etc/dnsmasq.d/vps-fengjin.conf 2>/dev/null; then
    cat "$WORKDIR/dnsmasq.conf" >/etc/dnsmasq.d/vps-fengjin.conf
    _dm_changed=1
  fi
  if ! command -v dnsmasq >/dev/null 2>&1 && ! pm_install dnsmasq; then
    dnsmasq_clear
    return 1
  fi
  if ! dnsmasq_reads_confdir; then
    [ -f /etc/dnsmasq.conf ] || : >/etc/dnsmasq.conf
    printf '\n%s\n' "conf-dir=/etc/dnsmasq.d/,*.conf" >>/etc/dnsmasq.conf
    printf '%s\n' 1 >"$CFG/dnsmasq.confdir"
    _dm_changed=1
  fi
  if [ "$_dm_shared" = 1 ]; then
    if ! dnsmasq --test >/dev/null 2>&1; then
      dnsmasq_clear
      return 1
    fi
    if [ "$_dm_changed" = 1 ] || ! dnsmasq_up; then
      restart_dnsmasq || { dnsmasq_clear; return 1; }
    fi
    return 0
  fi
  if ! dnsmasq --test --conf-file=/etc/dnsmasq.d/vps-fengjin.conf >/dev/null 2>&1; then
    dnsmasq_clear
    return 1
  fi
  if [ ! -f "$CFG/resolv.conf.link" ] && [ -L /etc/resolv.conf ]; then
    _dm_link=$(readlink /etc/resolv.conf 2>/dev/null)
    [ -n "$_dm_link" ] && printf '%s\n' "$_dm_link" >"$CFG/resolv.conf.link"
  fi
  if [ ! -f "$CFG/resolv.conf.bak" ] && [ -f /etc/resolv.conf ] \
    && ! grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null; then
    cp /etc/resolv.conf "$CFG/resolv.conf.bak" 2>/dev/null || true
  fi
  printf '%s\n' 1 >"$CFG/dnsmasq.owned"
  if [ "$_dm_changed" = 1 ] || ! dnsmasq_up; then
    restart_dnsmasq || { dnsmasq_clear; return 1; }
  fi
  # 双重校验：1) 能正常解析外部网站（避免断网）；2) 确实拦截了名单中的域名。
  _dm_probe=$(pick_probe_domain)
  if [ -z "$(resolve_probe "$_dm_probe" 127.0.0.1)" ]; then
    dnsmasq_clear
    return 1
  fi
  _dm_first=$(head -n 1 "$CFG/dns.list" 2>/dev/null)
  if [ -n "$_dm_first" ] && [ -n "$(resolve_probe "$_dm_first" 127.0.0.1)" ]; then
    dnsmasq_clear
    return 1
  fi
  # 切换系统 DNS：若 /etc/resolv.conf 是软链接（如 Ubuntu systemd-resolved），安全替换并在关闭时原样恢复。
  if [ -L /etc/resolv.conf ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] \
      && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
      printf '%s\n' 1 >"$CFG/resolved.was_active"
    fi
    if ! printf '%s\n' "# vps-fengjin managed" "nameserver 127.0.0.1" >/etc/resolv.conf.vps-fengjin.tmp 2>/dev/null \
      || ! mv -f /etc/resolv.conf.vps-fengjin.tmp /etc/resolv.conf 2>/dev/null; then
      rm -f /etc/resolv.conf.vps-fengjin.tmp 2>/dev/null
      say_warn "/etc/resolv.conf 无法修改，改为 /etc/hosts 方式。"
      dnsmasq_clear
      return 1
    fi
    if [ -f "$CFG/resolved.was_active" ]; then
      systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
    fi
  else
    if ! printf '%s\n' "# vps-fengjin managed" "nameserver 127.0.0.1" >/etc/resolv.conf 2>/dev/null; then
      say_warn "/etc/resolv.conf 为只读文件，改为 /etc/hosts 方式。"
      dnsmasq_clear
      return 1
    fi
  fi
  return 0
}

dns_apply() {
  case $1 in
    hosts)
      dnsmasq_clear
      hosts_apply
      ;;
    dnsmasq)
      hosts_clear
      if ! dnsmasq_apply; then
        say_warn "本地 DNS 服务（dnsmasq）未能接管，已自动降级为 /etc/hosts 拦截（仅覆盖主域名与 www）。"
        printf '%s\n' hosts >"$CFG/dns.method"
        hosts_apply
      fi
      ;;
    *)
      hosts_clear
      dnsmasq_clear
      ;;
  esac
}

# load_rules [1=同时应用域名配置]
load_rules() {
  probe_firewall
  _lr_method=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  if [ "$_lr_method" = string ] && { [ "$FW_BACKEND" != iptables ] || [ "$V4_STRING" != 1 ]; }; then
    if command -v dnsmasq >/dev/null 2>&1; then
      _lr_method=dnsmasq
    else
      say_warn "当前防火墙不支持按域名匹配，改为 /etc/hosts 方式。"
      _lr_method=hosts
    fi
    printf '%s\n' "$_lr_method" >"$CFG/dns.method"
  fi
  if [ "$FW_BACKEND" = none ]; then
    dns_apply "$_lr_method" || return 1
    return 0
  fi
  apply_firewall || return 1
  if [ "${1:-0}" = 1 ]; then
    dns_apply "$_lr_method" || return 1
  elif [ "$_lr_method" = dnsmasq ] && ! dns_live; then
    # 开机时若 DHCP 重写了 resolv.conf 或 dnsmasq 未起，自动恢复接管。
    dns_apply dnsmasq || true
  fi
  [ "$_lr_method" = string ] && flush_dns_cache
  return 0
}

disable_all() {
  remove_firewall
  hosts_clear
  dnsmasq_clear
}

#----------------------------------------------------------------------
# DNS 探测与上游记录
#----------------------------------------------------------------------

pick_resolver() {
  RESOLVER=none
  for _r in dig host nslookup drill getent; do
    if command -v "$_r" >/dev/null 2>&1; then
      RESOLVER=$_r
      return 0
    fi
  done
}

ensure_resolver() {
  pick_resolver
  case $RESOLVER in dig|host|nslookup|drill) return 0 ;; esac
  [ "${1:-}" = setup ] || return 0
  need_cmd dig dnsutils bind9-dnsutils bind-utils bind-tools bind-dig bind || true
  pick_resolver
}

with_timeout() {
  _wt_secs=$1
  shift
  if [ -z "${TIMEOUT_STYLE:-}" ]; then
    TIMEOUT_STYLE=none
    if timeout 1 true >/dev/null 2>&1; then
      TIMEOUT_STYLE=plain
    elif timeout -t 1 true >/dev/null 2>&1; then
      TIMEOUT_STYLE=busybox
    fi
  fi
  case $TIMEOUT_STYLE in
    plain) timeout "$_wt_secs" "$@" ;;
    busybox) timeout -t "$_wt_secs" "$@" ;;
    *) "$@" ;;
  esac
}

resolve_probe() {
  pick_resolver
  case $RESOLVER in
    dig) dig "@$2" +time=2 +tries=1 +short "$1" A 2>/dev/null ;;
    host) host -W 2 -t A "$1" "$2" 2>/dev/null ;;
    nslookup) with_timeout 5 nslookup "$1" "$2" 2>/dev/null ;;
    drill) with_timeout 5 drill "@$2" "$1" A 2>/dev/null ;;
    *) : ;;
  esac | awk -v server="$2" '
    { for (i = 1; i <= NF; i++)
        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i != server) print $i }'
}

# 用本机默认解析器做一次真实解析测试（vps-fengjin test 使用）。
# $2 = hosts 时优先用 getent（尊重 /etc/hosts），否则直接查 DNS。
resolve_system() {
  if [ "${2:-}" = hosts ] && command -v getent >/dev/null 2>&1; then
    with_timeout 3 getent ahosts "$1" 2>/dev/null | awk '
      $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || $1 ~ /:/ { print $1 }
    ' | LC_ALL=C sort -u | head -n 4
    return 0
  fi
  pick_resolver
  case $RESOLVER in
    dig)
      dig +time=2 +tries=1 +short "$1" A 2>/dev/null \
        | awk '$0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print }' | head -n 4
      ;;
    host)
      host -W 2 -t A "$1" 2>/dev/null \
        | awk '$2 == "has" && $3 == "address" && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $4 }' | head -n 4
      ;;
    nslookup)
      # 只取 Name: 之后的解析结果，避免把顶部 Server: 8.8.8.8 误判成解析成功。
      with_timeout 3 nslookup "$1" 2>/dev/null | awk '
        /^Name:/ { ans = 1; next }
        ans {
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i
          }
        }
      ' | head -n 4
      ;;
    drill)
      with_timeout 3 drill "$1" A 2>/dev/null | awk '
        /^;; ANSWER SECTION:/ { ans = 1; next }
        /^;;/ { ans = 0 }
        ans && $4 == "A" && $5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $5 }
      ' | head -n 4
      ;;
    getent)
      with_timeout 3 getent ahosts "$1" 2>/dev/null \
        | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1 }' | LC_ALL=C sort -u | head -n 4
      ;;
    *) : ;;
  esac
}

save_upstreams() {
  if grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null && [ -s "$CFG/upstream.dns" ]; then
    return 0
  fi
  : >"$CFG/upstream.dns"
  for _sf in /etc/resolv.conf /run/systemd/resolve/resolv.conf; do
    [ -s "$CFG/upstream.dns" ] && break
    awk '
      $1 == "nameserver" {
        sub(/\r$/, "", $2)
        if ($2 != "" && $2 != "127.0.0.1" && $2 != "127.0.0.53" && $2 != "127.0.0.54" && $2 != "::1") print $2
      }
    ' "$_sf" >"$CFG/upstream.dns" 2>/dev/null
  done
  if [ ! -s "$CFG/upstream.dns" ]; then
    if ipv6_on && command -v ip >/dev/null 2>&1 && ! ip -4 route show default 2>/dev/null | grep -q .; then
      printf '%s\n' "2606:4700:4700::1111" "2001:4860:4860::8888" >"$CFG/upstream.dns"
    else
      printf '%s\n' 1.1.1.1 8.8.8.8 >"$CFG/upstream.dns"
    fi
  fi
}

choose_dns_method() {
  # $1 = 域名条数。域名不分端口，始终在解析层拦截（含子域名）。
  if [ "$1" -eq 0 ]; then
    printf '%s\n' none
  elif [ "$OS_ID" = openwrt ]; then
    printf '%s\n' dnsmasq
  elif [ "$FW_BACKEND" = iptables ] && [ "$V4_STRING" = 1 ] && [ "$1" -le 400 ]; then
    # 400 个以内域名优先用防火墙子链直接拦 DNS 查询：不改系统 DNS、无额外服务、含子域名。
    printf '%s\n' string
  elif command -v dnsmasq >/dev/null 2>&1 || [ "${PM:-none}" != none ]; then
    # 超过 400 个域名、nftables 或无防火墙权限：优先用 dnsmasq，支持大名单与子域名。
    printf '%s\n' dnsmasq
  else
    printf '%s\n' hosts
  fi
}

#----------------------------------------------------------------------
# 防误封保护：自动跳过 SSH 登录 IP、本机地址、上游 DNS
#----------------------------------------------------------------------

ssh_peers_from_proc() {
  _sp_ports=22
  set -- ${SSH_CONNECTION:-}
  [ -n "${4:-}" ] && _sp_ports="$_sp_ports $4"
  for _sp_cfg in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    [ -r "$_sp_cfg" ] || continue
    _sp_ports="$_sp_ports $(awk 'tolower($1) == "port" { print $2 }' "$_sp_cfg" 2>/dev/null)"
  done
  _sp_hex=""
  for _p in $_sp_ports; do
    case $_p in
      ''|*[!0-9]*) continue ;;
      *) _sp_hex="${_sp_hex}$(printf '%04X ' "$_p" 2>/dev/null)" ;;
    esac
  done
  for _sp_f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$_sp_f" ] || continue
    awk -v ports=" $_sp_hex" '
      function h2d(h,   i, v) {
        v = 0
        h = toupper(h)
        for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1
        return v
      }
      function word(h) {
        return substr(h, 7, 2) substr(h, 5, 2) substr(h, 3, 2) substr(h, 1, 2)
      }
      function dotted(h) {
        return h2d(substr(h, 1, 2)) "." h2d(substr(h, 3, 2)) "." h2d(substr(h, 5, 2)) "." h2d(substr(h, 7, 2))
      }
      NR > 1 && $4 == "01" {
        split($2, loc, ":")
        split($3, rem, ":")
        if (index(ports, " " toupper(loc[2]) " ") == 0) next
        h = rem[1]
        if (length(h) == 8) { print dotted(word(h)); next }
        if (length(h) != 32) next
        full = word(substr(h, 1, 8)) word(substr(h, 9, 8)) word(substr(h, 17, 8)) word(substr(h, 25, 8))
        if (toupper(substr(full, 1, 24)) == "00000000000000000000FFFF") { print dotted(substr(full, 25, 8)); next }
        out = ""
        for (i = 0; i < 8; i++) out = out (i ? ":" : "") tolower(substr(full, i * 4 + 1, 4))
        print out
      }
    ' "$_sp_f" 2>/dev/null
  done
}

collect_excludes() {
  _ce_out=$1
  : >"$_ce_out"
  : >"$WORKDIR/ssh.now"
  for _ce_v in "${SSH_CONNECTION:-}" "${SSH_CLIENT:-}"; do
    set -- $_ce_v
    [ -n "${1:-}" ] && printf '%s\n' "${1%%%*}" >>"$WORKDIR/ssh.now"
  done
  # sudo 运行时会清掉 SSH 环境变量，所以把 /proc 里正在连 sshd 的来源也一起记下来。
  ssh_peers_from_proc >>"$WORKDIR/ssh.now"
  if [ -s "$WORKDIR/ssh.now" ]; then
    cat "$WORKDIR/ssh.now" "$CFG/ssh.peers" 2>/dev/null | LC_ALL=C sort -u | tail -n 20 >"$WORKDIR/ssh.peers"
    cat "$WORKDIR/ssh.peers" >"$CFG/ssh.peers"
  fi
  cat "$CFG/ssh.peers" >>"$_ce_out" 2>/dev/null
  if command -v ip >/dev/null 2>&1; then
    ip -o addr show 2>/dev/null | awk '$3 == "inet" || $3 == "inet6" { split($4, a, "/"); print a[1] }' >>"$_ce_out"
  fi
  cat "$CFG/upstream.dns" >>"$_ce_out" 2>/dev/null
  LC_ALL=C sort -u "$_ce_out" -o "$_ce_out"
}

filter_family() {
  : >"$WORKDIR/skip.$1"
  : >"$3"
  [ -s "$2" ] || return 0
  LC_ALL=C sort -u "$2" | awk -v fam="$1" '
    NF { print (index($0, "/") > 0 ? "net" : "ip") fam "\t" $0 }
  ' | fengjin_awk overlap peers="$4" skipfile="$WORKDIR/skip.$1" \
    | awk -F '\t' 'NF >= 2 { print $2 }' >"$3"
}

rebuild_ips() {
  for _f in v4.raw v6.raw dns.names; do
    : >"$WORKDIR/$_f"
  done
  awk -F '\t' -v w="$WORKDIR" '
    $1 == "ip4" || $1 == "net4" { print $2 > (w "/v4.raw"); next }
    $1 == "ip6" || $1 == "net6" { print $2 > (w "/v6.raw"); next }
    $1 == "domain" || $1 == "suffix" { print $2 > (w "/dns.names") }
  ' "$CFG/list.txt"
  LC_ALL=C sort -u "$WORKDIR/dns.names" -o "$WORKDIR/dns.list"
  _rb_method=$(choose_dns_method "$(count_lines "$WORKDIR/dns.list")")
  if [ "$FW_BACKEND" = none ]; then
    : >"$CFG/v4"
    : >"$CFG/v6"
    cat "$WORKDIR/dns.list" >"$CFG/dns.list"
    printf '%s\n' "$_rb_method" >"$CFG/dns.method"
    return 0
  fi
  collect_excludes "$WORKDIR/exclude"
  filter_family 4 "$WORKDIR/v4.raw" "$CFG/v4" "$WORKDIR/exclude"
  filter_family 6 "$WORKDIR/v6.raw" "$CFG/v6" "$WORKDIR/exclude"
  cat "$WORKDIR/dns.list" >"$CFG/dns.list"
  printf '%s\n' "$_rb_method" >"$CFG/dns.method"
  cat "$WORKDIR/skip.4" "$WORKDIR/skip.6" >"$WORKDIR/skipped" 2>/dev/null
  if [ -s "$WORKDIR/skipped" ]; then
    say_warn "防误封保护：已自动跳过以下包含 SSH 来源、本机地址或 DNS 的条目："
    head -n 8 "$WORKDIR/skipped" | awk -F '\t' '{ print "    " $1 "（保护了 " $2 "）" }'
  fi
}

#----------------------------------------------------------------------
# 安装快捷命令、开机自启与定时巡检
#----------------------------------------------------------------------

installed_bin() {
  if [ -x "$BIN_DEFAULT" ]; then
    printf '%s\n' "$BIN_DEFAULT"
  elif [ -x /usr/sbin/vps-fengjin ]; then
    printf '%s\n' /usr/sbin/vps-fengjin
  else
    printf '%s\n' "$BIN_DEFAULT"
  fi
}

install_self() {
  _is_dest=$BIN_DEFAULT
  mkdir -p /usr/local/sbin 2>/dev/null || _is_dest=/usr/sbin/vps-fengjin
  _is_src=$0
  case $_is_src in
    /*) ;;
    *) _is_src=$(pwd)/$_is_src ;;
  esac
  if [ ! -f "$_is_src" ] || ! grep -q 'vps-fengjin-onekey-begin' "$_is_src" 2>/dev/null; then
    [ -x "$(installed_bin)" ] && return 0
    die "请先将脚本下载为文件再运行（可直接使用 README 中的一键命令），否则无法安装 vps-fengjin 快捷命令。"
  fi
  if [ "$_is_src" != "$_is_dest" ]; then
    cp "$_is_src" "$_is_dest.new" && chmod 755 "$_is_dest.new" && mv -f "$_is_dest.new" "$_is_dest"
  fi
  # 部分系统默认 PATH 不含 /usr/local/sbin，额外在 /usr/local/bin 建软链接确保随时能打 vps-fengjin。
  if [ -d /usr/local/bin ] && [ "$_is_dest" != "$BIN_LINK" ]; then
    ln -sf "$_is_dest" "$BIN_LINK" 2>/dev/null || true
  fi
}

write_systemd() {
  mkdir -p /etc/systemd/system
  cat >/etc/systemd/system/vps-fengjin.service <<EOF
[Unit]
Description=Apply saved outbound block list (vps-fengjin)
After=network.target firewalld.service ufw.service netfilter-persistent.service nftables.service iptables.service docker.service dnsmasq.service

[Service]
Type=oneshot
ExecStart=$1 apply-rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/vps-fengjin-refresh.service <<EOF
[Unit]
Description=Re-apply outbound block list (vps-fengjin)

[Service]
Type=oneshot
ExecStart=$1 refresh
EOF
  cat >/etc/systemd/system/vps-fengjin-refresh.timer <<EOF
[Unit]
Description=Re-apply outbound block list every 6 hours (vps-fengjin)

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable vps-fengjin.service >/dev/null 2>&1
}

append_marked() {
  touch "$1"
  strip_marked_file "$1"
  awk -v line="$2" '
    { lines[++n] = $0 }
    END {
      at = n + 1
      for (i = n; i >= 1; i--) {
        if (lines[i] ~ /^[ \t]*exit[ \t]+0[ \t]*$/) { at = i; break }
        if (lines[i] !~ /^[ \t]*$/) break
      }
      for (i = 1; i < at; i++) print lines[i]
      print "# BEGIN vps-fengjin"
      print line
      print "# END vps-fengjin"
      for (i = at; i <= n; i++) print lines[i]
    }
  ' "$1" >"$WORKDIR/marked.new"
  cat "$WORKDIR/marked.new" >"$1"
}

install_persistence() {
  _ip_bin=$(installed_bin)
  PERSIST_OK=1
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    write_systemd "$_ip_bin"
    systemctl enable --now vps-fengjin-refresh.timer >/dev/null 2>&1
    printf '%s\n' 1 >"$WORKDIR/persist.ok"
    return 0
  fi
  if [ -f /etc/openwrt_release ]; then
    cat >/etc/init.d/vps-fengjin <<EOF
#!/bin/sh /etc/rc.common
START=95
start() { $_ip_bin apply-rules; }
EOF
    chmod 755 /etc/init.d/vps-fengjin
    /etc/init.d/vps-fengjin enable >/dev/null 2>&1
    append_marked /etc/firewall.user "$_ip_bin apply-rules"
  elif command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ]; then
    cat >/etc/init.d/vps-fengjin <<EOF
#!/sbin/openrc-run
name="vps-fengjin"
description="Apply saved outbound block list"
depend() { after net firewall; }
start() { $_ip_bin apply-rules; }
EOF
    chmod 755 /etc/init.d/vps-fengjin
    rc-update add vps-fengjin default >/dev/null 2>&1
  elif [ -f /etc/rc.local ]; then
    append_marked /etc/rc.local "$_ip_bin apply-rules"
    chmod +x /etc/rc.local 2>/dev/null || true
  else
    PERSIST_OK=0
  fi
  printf '%s\n' "$PERSIST_OK" >"$WORKDIR/persist.ok"
  remove_cron
  if [ -d /etc/cron.d ]; then
    printf '17 */6 * * * root %s refresh >/dev/null 2>&1\n' "$_ip_bin" >/etc/cron.d/vps-fengjin
  elif [ -d /etc/crontabs ]; then
    printf '17 */6 * * * %s refresh >/dev/null 2>&1\n' "$_ip_bin" >>/etc/crontabs/root
  fi
}

remove_cron() {
  rm -f /etc/cron.d/vps-fengjin
  if [ -f /etc/crontabs/root ] && grep -q 'vps-fengjin refresh' /etc/crontabs/root; then
    grep -v 'vps-fengjin refresh' /etc/crontabs/root >"$WORKDIR/cron.root"
    cat "$WORKDIR/cron.root" >/etc/crontabs/root
  fi
}

remove_persistence() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now vps-fengjin.service vps-fengjin-refresh.timer >/dev/null 2>&1
  fi
  rm -f /etc/systemd/system/vps-fengjin.service \
    /etc/systemd/system/vps-fengjin-refresh.service \
    /etc/systemd/system/vps-fengjin-refresh.timer
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1
  fi
  command -v rc-update >/dev/null 2>&1 && rc-update del vps-fengjin default >/dev/null 2>&1
  if [ -f /etc/openwrt_release ] && [ -x /etc/init.d/vps-fengjin ]; then
    /etc/init.d/vps-fengjin disable >/dev/null 2>&1
  fi
  rm -f /etc/init.d/vps-fengjin
  remove_cron
  strip_marked_file /etc/firewall.user
  strip_marked_file /etc/rc.local
}

#----------------------------------------------------------------------
# 名单导入、识别、预览与在线更新
#----------------------------------------------------------------------

fetch_url() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --max-time 120 --max-filesize "$LIST_MAX_BYTES" -o "$2" "$1" 2>"$WORKDIR/fetch.err"
    _fu_rc=$?
    [ "$_fu_rc" -eq 0 ] && return 0
    if [ "$_fu_rc" -eq 63 ]; then
      say_err "链接文件超过 ${LIST_MAX_MB}MB 上限，未下载。"
      return 2
    fi
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 30 -O "$2" "$1" 2>"$WORKDIR/fetch.err" && return 0
    return 1
  fi
  say_err "系统缺少 curl / wget，无法下载在线名单。"
  return 1
}

read_source() {
  list_limits
  : >"$2"
  case $1 in
    http://*|https://*)
      _rs_url=$(normalize_url "$1")
      if [ "$_rs_url" != "$1" ]; then
        say_info "检测到 GitHub 网页链接，已自动转为直链下载。"
      fi
      say_dim "  正在下载名单..."
      fetch_url "$_rs_url" "$2"
      _rs_rc=$?
      if [ "$_rs_rc" -ne 0 ]; then
        if [ "$_rs_rc" -eq 1 ]; then
          say_err "下载失败，请检查链接是否正确，或服务器能否访问该网址。"
          [ -s "$WORKDIR/fetch.err" ] && say_dim "  原因：$(head -n 1 "$WORKDIR/fetch.err")"
        fi
        return 1
      fi
      ;;
    *://*)
      say_err "只支持 http:// 或 https:// 开头的链接。"
      return 1
      ;;
    -)
      save_stdin
      cat <&4 >"$2"
      ;;
    *)
      if [ ! -f "$1" ]; then
        say_err "找不到这个文件：$1"
        return 1
      fi
      if [ "$(wc -c <"$1")" -gt "$LIST_MAX_BYTES" ]; then
        say_err "文件超过 ${LIST_MAX_MB}MB，这台机器内存吃不消。"
        return 1
      fi
      cat "$1" >"$2"
      ;;
  esac
  if [ "$(wc -c <"$2")" -gt "$LIST_MAX_BYTES" ]; then
    say_err "名单超过 ${LIST_MAX_MB}MB，这台机器内存吃不消。"
    return 1
  fi
  case $(dd if="$2" bs=2048 count=1 2>/dev/null | tr 'A-Z' 'a-z') in
    *'<html'*|*'<!doctype'*)
      say_err "下载到的是普通网页而不是纯文本名单，请确认链接指向的是规则原文。"
      return 1
      ;;
  esac
  return 0
}

bad_reason() {
  case $1 in
    wide) printf '%s\n' "网段过大（防止误封整台机器）" ;;
    local) printf '%s\n' "本机或保留地址" ;;
    keyword) printf '%s\n' "关键词规则范围太广，不支持" ;;
    unsupported) printf '%s\n' "不支持此类规则" ;;
    *) printf '%s\n' "格式无法识别" ;;
  esac
}

summarize_list() {
  N_DOMAIN=0
  N_SUFFIX=0
  N_IP=0
  N_BAD=0
  [ -f "$1" ] || return 0
  eval "$(awk -F '\t' '
    $1 == "domain" { d++ }
    $1 == "suffix" { s++ }
    $1 ~ /^(ip|net)[46]$/ { i++ }
    $1 == "bad" { b++ }
    END { printf "N_DOMAIN=%d N_SUFFIX=%d N_IP=%d N_BAD=%d\n", d, s, i, b }
  ' "$1" 2>/dev/null)"
}

# 生成几条示例文本，如 "baidu.com, qq.com 等"，让小白直观确认解析结果。
sample_items() {
  # $1 = list 文件, $2 = domain|ip, $3 = 最多几条
  [ -s "$1" ] || return 0
  awk -F '\t' -v want="$2" -v lim="${3:-3}" '
    (want == "domain" && ($1 == "domain" || $1 == "suffix")) || (want == "ip" && $1 ~ /^(ip|net)[46]$/) {
      c++
      if (c <= lim) out = (out == "" ? $2 : out "、" $2)
    }
    END {
      if (out != "") printf "%s%s\n", out, (c > lim ? " 等" : "")
    }
  ' "$1"
}

show_bads() {
  [ "$N_BAD" -gt 0 ] || return 0
  say_warn "已跳过 $N_BAD 条无效或不支持的记录（最多展示 5 条）："
  awk -F '\t' '$1 == "bad" { print $2 "\t" $3 }' "$1" | head -n 5 | while IFS='	' read -r _sb_code _sb_rest; do
    printf '    %s：%s\n' "$(bad_reason "$_sb_code")" "$_sb_rest"
  done
}

classify_raw() {
  fengjin_awk classify <"$1" >"$WORKDIR/class.all"
  list_limits
  awk -F '\t' -v cap="$LIST_MAX_ITEMS" -v w="$WORKDIR" '
    BEGIN { printf "" > (w "/class.keep") }
    $1 == "bad" { next }
    $1 == "domain" || $1 == "suffix" { if (++n > cap) next }
    { print > (w "/class.keep") }
    END { print n + 0 > (w "/class.nnames") }
  ' "$WORKDIR/class.all"
  _cr_n=$(cat "$WORKDIR/class.nnames")
  if [ "$_cr_n" -gt "$LIST_MAX_ITEMS" ]; then
    say_warn "这份名单含 $_cr_n 个域名，本机内存上限为 $LIST_MAX_ITEMS 个，超出部分已截断。"
  fi
  LC_ALL=C sort -u "$WORKDIR/class.keep" >"$2"
}

cap_list() {
  list_limits
  _cl_n=$(awk -F '\t' '$1 == "domain" || $1 == "suffix" { c++ } END { print c + 0 }' "$1")
  [ "$_cl_n" -gt "$LIST_MAX_ITEMS" ] || return 0
  say_warn "多份名单合并后域名超过 $LIST_MAX_ITEMS 个，本机仅保留前 $LIST_MAX_ITEMS 个。"
  awk -F '\t' -v cap="$LIST_MAX_ITEMS" '
    $1 == "domain" || $1 == "suffix" { if (++c > cap) next }
    { print }
  ' "$1" >"$WORKDIR/list.cap"
  cat "$WORKDIR/list.cap" >"$1"
}

clean_name() {
  printf '%s' "$1" | tr -d '\000-\037' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//'
}

# 列出名单目录：saved=已生效, pending=本次新加, all=已生效+本次新加
source_dirs() {
  if [ "$1" != pending ] && [ -d "$CFG/sources" ]; then
    for _sd in $(ls "$CFG/sources" 2>/dev/null | LC_ALL=C sort -n); do
      [ -d "$CFG/sources/$_sd" ] || continue
      if [ "$1" = all ] && grep -qxF "$CFG/sources/$_sd" "$WORKDIR/del.list" 2>/dev/null; then
        continue
      fi
      printf '%s\n' "$CFG/sources/$_sd"
    done
  fi
  if [ "$1" != saved ] && [ -d "${PENDING:-}" ]; then
    for _sd in $(ls "$PENDING" 2>/dev/null | LC_ALL=C sort -n); do
      [ -d "$PENDING/$_sd" ] && printf '%s\n' "$PENDING/$_sd"
    done
  fi
}

count_sources() {
  source_dirs "$1" | awk 'END { print NR + 0 }'
}

next_source_id() {
  { ls "$CFG/sources" 2>/dev/null; ls "${PENDING:-/nonexistent}" 2>/dev/null; } \
    | awk '$1 ~ /^[0-9]+$/ && $1 + 0 > m { m = $1 + 0 } END { print m + 1 }'
}

show_source_line() {
  _ss_d=$2
  _ss_name=$(cat "$_ss_d/name" 2>/dev/null)
  _ss_origin=$(cat "$_ss_d/origin" 2>/dev/null)
  set -- "$1" $(cat "$_ss_d/count" 2>/dev/null) 0 0 0
  case $(cat "$_ss_d/kind" 2>/dev/null) in
    url) _ss_from="在线链接：$_ss_origin" ;;
    file) _ss_from="本地文件：$_ss_origin" ;;
    paste) _ss_from="手动输入 / 粘贴" ;;
    *) _ss_from="旧版本迁移" ;;
  esac
  printf '  %s) %s  (域名 %s 个，IP/网段 %s 个)\n' "$1" "$_ss_name" "$(($2 + $3))" "$4"
  say_dim "     $_ss_from"
}

migrate_sources() {
  [ -d "$CFG/sources" ] && return 0
  [ -s "$CFG/list.txt" ] || return 0
  mkdir -p "$CFG/sources/1"
  cp "$CFG/list.txt" "$CFG/sources/1/list"
  summarize_list "$CFG/list.txt"
  printf '%s %s %s\n' "$N_DOMAIN" "$N_SUFFIX" "$N_IP" >"$CFG/sources/1/count"
  printf '%s\n' "原有名单" >"$CFG/sources/1/name"
  printf '%s\n' old >"$CFG/sources/1/kind"
  : >"$CFG/sources/1/origin"
}

add_source() {
  _as_id=$(next_source_id)
  _as_d=$PENDING/$_as_id
  mkdir -p "$_as_d"
  classify_raw "$4" "$_as_d/list"
  summarize_list "$WORKDIR/class.all"
  show_bads "$WORKDIR/class.all"
  summarize_list "$_as_d/list"
  _as_dom=$((N_DOMAIN + N_SUFFIX))
  if [ $((_as_dom + N_IP)) -eq 0 ]; then
    say_err "没有识别到可用的域名或 IP，未添加。"
    rm -rf "$_as_d"
    return 1
  fi
  printf '%s %s %s\n' "$N_DOMAIN" "$N_SUFFIX" "$N_IP" >"$_as_d/count"
  printf '%s\n' "$1" >"$_as_d/kind"
  printf '%s\n' "$2" >"$_as_d/origin"
  printf '%s\n' "$3" >"$_as_d/name"
  _as_ex=""
  _as_sd=$(sample_items "$_as_d/list" domain 3)
  _as_si=$(sample_items "$_as_d/list" ip 2)
  [ -n "$_as_sd" ] && _as_ex="域名示例：$_as_sd"
  if [ -n "$_as_si" ]; then
    _as_ex="${_as_ex:+${_as_ex}；}IP示例：$_as_si"
  fi
  say_ok "已添加「${3}」：域名 $_as_dom 个，IP / 网段 $N_IP 个"
  [ -n "$_as_ex" ] && say_dim "  $_as_ex"
  if [ "${FW_BACKEND:-}" = none ] && [ "$N_IP" -gt 0 ] && [ "$_as_dom" -eq 0 ]; then
    say_warn "提醒：当前机器仅支持封域名，这份名单里只有 IP/网段，将无法拦截。"
  fi
  return 0
}

add_from() {
  _af_src=$(printf '%s' "$1" | sed "s/^[\"']//;s/[\"']\$//")
  case $_af_src in
    "~/"*) _af_src=$HOME/${_af_src#"~/"} ;;
  esac
  read_source "$_af_src" "$WORKDIR/raw.txt" || return 1
  case $_af_src in
    http://*|https://*)
      _af_norm=$(normalize_url "$_af_src")
      _af_def=$(printf '%s' "$_af_norm" | sed 's/[?#].*//;s|/*$||;s|.*/||')
      add_source url "$_af_norm" "${_af_def:-在线名单}" "$WORKDIR/raw.txt"
      ;;
    -) add_source paste "" "标准输入名单" "$WORKDIR/raw.txt" ;;
    *) add_source file "$_af_src" "$(basename "$_af_src")" "$WORKDIR/raw.txt" ;;
  esac
}

# 直接解析一行用户输入（如 "baidu.com" 或 "baidu.com, qq.com 1.2.3.4"）。
add_inline() {
  printf '%s\n' "$1" >"$WORKDIR/raw.txt"
  _ai_id=$(next_source_id)
  add_source paste "" "手动添加 $_ai_id" "$WORKDIR/raw.txt"
}

add_paste() {
  input_init
  say ""
  say "请输入或粘贴要封禁的域名 / IP（一行一个，或用空格/逗号隔开均可）："
  say_dim "  常见写法都能认：baidu.com、*.qq.com、1.2.3.4、1.2.3.0/24、Clash 规则、Hosts 等"
  say_dim "  全部输入完后，另起一行输入 ok 回车结束（也可以输入 end 或按 Ctrl+D）；首行直接回车返回。"
  : >"$WORKDIR/raw.txt"
  _ap_n=0
  while IFS= read -r _ap_line <&3; do
    _ap_trim=$(printf '%s' "$_ap_line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ "$_ap_n" -eq 0 ] && [ -z "$_ap_trim" ]; then
      say_info "已返回。"
      return 1
    fi
    _ap_low=$(printf '%s' "$_ap_trim" | tr 'A-Z' 'a-z')
    case $_ap_low in
      ok|end|done|完成) break ;;
    esac
    printf '%s\n' "$_ap_line" >>"$WORKDIR/raw.txt"
    _ap_n=$((_ap_n + 1))
    if [ "$_ap_n" -ge 100000 ]; then
      say_warn "已接收 100000 行上限。超大名单建议保存成文件或用在线链接导入。"
      break
    fi
  done
  if [ "$_ap_n" -eq 0 ]; then
    say_warn "没有输入内容。"
    return 1
  fi
  add_source paste "" "手动添加 $(next_source_id)" "$WORKDIR/raw.txt"
}

# merge_sources all|pending 输出文件
# 明确区分「合并全部」与「仅合并本次新加」，修复更换整套名单时残留旧规则的问题。
merge_sources() {
  _ms_scope=$1
  _ms_out=$2
  source_dirs "$_ms_scope" | while IFS= read -r _mg_d; do
    [ -f "$_mg_d/list" ] && cat "$_mg_d/list"
  done | LC_ALL=C sort -u >"$_ms_out"
  cap_list "$_ms_out"
}

preview_source() {
  _ps_d=$1
  _ps_name=$(cat "$_ps_d/name" 2>/dev/null)
  _ps_total=$(count_lines "$_ps_d/list")
  say ""
  say "${C_BOLD}「${_ps_name}」内容预览（共 $_ps_total 条，显示前 30 条）：${C_NC}"
  awk -F '\t' '
    NR <= 30 {
      if ($1 == "domain" || $1 == "suffix") printf "  [域名] %s\n", $2
      else if ($1 ~ /^(ip|net)[46]$/) printf "  [IP]   %s\n", $2
    }
  ' "$_ps_d/list"
  [ "$_ps_total" -gt 30 ] && say_dim "  ... 还有 $((_ps_total - 30)) 条未显示"
}

#----------------------------------------------------------------------
# 生效、回滚、状态与实时测试
#----------------------------------------------------------------------

scope_text() {
  if [ "$1" = all ]; then
    printf '%s\n' "全局封禁（本机及所有代理节点）"
  else
    printf '%s\n' "仅封目标端口 ${2}（域名仍全局拦截）"
  fi
}

dns_method_text() {
  case $1 in
    string) printf '%s\n' "防火墙直拦 DNS 查询（不改动系统 DNS，含子域名）" ;;
    dnsmasq) printf '%s\n' "本地 DNS 过滤（dnsmasq，支持大名单与子域名）" ;;
    hosts) printf '%s\n' "/etc/hosts 屏蔽（仅覆盖主域名与 www）" ;;
    *) printf '%s\n' "无（名单中不含域名）" ;;
  esac
}

cfg_backup() {
  rm -rf "$WORKDIR/cfg.bak"
  HAD_CFG=0
  if [ -d "$CFG" ]; then
    cp -R "$CFG" "$WORKDIR/cfg.bak" && HAD_CFG=1
  fi
}

cfg_restore() {
  rm -rf "$CFG"
  [ "$HAD_CFG" = 1 ] && cp -R "$WORKDIR/cfg.bak" "$CFG"
}

activate() {
  mkdir -p "$CFG"
  [ -n "${OS_ID:-}" ] || detect_os
  save_upstreams
  if [ "${1:-setup}" = setup ]; then
    lowmem_prepare
    fw_precheck
  else
    probe_firewall
  fi
  printf '%s\n' "$FW_BACKEND" >"$CFG/backend"
  rebuild_ips
  if [ "${1:-setup}" = setup ] && [ "$(cat "$CFG/dns.method")" = dnsmasq ]; then
    ensure_resolver setup
  fi
  if [ ! -s "$CFG/v4" ] && [ ! -s "$CFG/v6" ] && [ "$(cat "$CFG/dns.method")" = none ]; then
    [ "$FW_BACKEND" = none ] && die "当前机器只能封域名，但名单里没有任何域名（IP/网段在此环境下无法拦截）。"
    die "名单里没有可生效的域名或 IP（可能全部触发了防误封跳过）。"
  fi
  load_rules 1 || exit 1
  printf '%s\n' 1 >"$CFG/enabled"
  write_status
  [ "${1:-setup}" = setup ] && install_persistence
  return 0
}

# apply_changes new|append|delete|keep [合并后的 list 文件]
apply_changes() {
  cfg_backup
  mkdir -p "$CFG"
  case $1 in
    new|append)
      [ "$1" = new ] && rm -rf "$CFG/sources" "$CFG/resolved.last"
      mkdir -p "$CFG/sources"
      for _ac_d in "$PENDING"/*; do
        [ -d "$_ac_d" ] || continue
        rm -rf "$CFG/sources/${_ac_d##*/}"
        mv "$_ac_d" "$CFG/sources/"
      done
      ;;
    delete)
      while IFS= read -r _ac_d; do
        [ -n "$_ac_d" ] && rm -rf "$_ac_d"
      done <"$WORKDIR/del.list"
      : >"$WORKDIR/del.list"
      ;;
    update)
      # 把暂存的在线名单更新写回正式目录（在 cfg_backup 之后，失败可完整回滚）
      for _ac_u in "$WORKDIR/upd_stage"/*; do
        [ -d "$_ac_u" ] || continue
        _ac_id=${_ac_u##*/}
        if [ -d "$CFG/sources/$_ac_id" ]; then
          cp "$_ac_u/list" "$CFG/sources/$_ac_id/list"
          cp "$_ac_u/count" "$CFG/sources/$_ac_id/count"
        fi
      done
      rm -rf "$WORKDIR/upd_stage"
      ;;
  esac
  [ -n "${2:-}" ] && cat "$2" >"$CFG/list.txt"
  printf '%s\n' "$MODE" >"$CFG/mode"
  printf '%s\n' "$PORTS" >"$CFG/ports"
  say ""
  say_info "正在应用封禁规则，请稍候..."
  if (activate setup); then
    _ac_v4=$(count_lines "$CFG/v4")
    _ac_v6=$(count_lines "$CFG/v6")
    _ac_dn=$(count_lines "$CFG/dns.list")
    _ac_be=$(cat "$CFG/backend" 2>/dev/null)
    _ac_pok=$(cat "$WORKDIR/persist.ok" 2>/dev/null || echo 1)
    say ""
    if [ "$_ac_be" = none ]; then
      say_ok "封禁已生效（仅封禁域名模式：$_ac_dn 个域名）"
      say_dim "  • 若代理节点此前已运行，建议重启一次节点程序让它使用新的 DNS。"
      say_dim "  • 受限容器重启后若未自动生效，运行 vps-fengjin on 即可恢复。"
    else
      say_ok "封禁已生效！已拦截 $_ac_dn 个域名、$((_ac_v4 + _ac_v6)) 条 IP/网段。"
      if [ "$_ac_pok" = 1 ]; then
        say_dim "  • 已配置开机自启，并每 6 小时自动巡检，防止被其他防火墙冲掉。"
      else
        say_dim "  • 当前环境无开机自启服务，重启后运行 vps-fengjin on 即可恢复。"
      fi
    fi
    return 0
  fi
  say_err "规则生效失败，正在自动还原修改前的配置..."
  hosts_clear
  dnsmasq_clear
  cfg_restore
  if [ "$HAD_CFG" = 1 ] && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
    PROBED=0
    (load_rules 1) >/dev/null 2>&1 || true
  else
    remove_firewall
  fi
  say_info "已完整恢复到操作前的状态，没有产生破坏。"
  return 1
}

write_status() {
  [ -n "${OS_PRETTY:-}" ] || detect_os
  _ws_method=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  _ws_be=$(cat "$CFG/backend" 2>/dev/null || echo none)
  summarize_list "$CFG/list.txt"
  {
    if [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
      printf '%s\n' "状态：运行中"
    else
      printf '%s\n' "状态：已暂停（名单保留）"
    fi
    printf '系统：%s\n' "${OS_PRETTY:-未知}"
    if [ "$_ws_be" = none ]; then
      printf '%s\n' "范围：全局封禁（受限环境：仅拦截域名）"
    else
      printf '范围：%s\n' "$(scope_text "$(cat "$CFG/mode" 2>/dev/null)" "$(cat "$CFG/ports" 2>/dev/null)")"
    fi
    printf '名单总计：域名 %s 个，IP / 网段 %s 个\n' "$((N_DOMAIN + N_SUFFIX))" "$N_IP"
    source_dirs saved >"$WORKDIR/status.idx"
    _ws_i=0
    while IFS= read -r _ws_d; do
      _ws_i=$((_ws_i + 1))
      _ws_n=$(cat "$_ws_d/name" 2>/dev/null)
      _ws_o=$(cat "$_ws_d/origin" 2>/dev/null)
      set -- $(cat "$_ws_d/count" 2>/dev/null) 0 0 0
      case $(cat "$_ws_d/kind" 2>/dev/null) in
        url) _ws_f="在线链接 $_ws_o" ;;
        file) _ws_f="本地文件 $_ws_o" ;;
        paste) _ws_f="手动输入" ;;
        *) _ws_f="旧版本迁移" ;;
      esac
      printf '  %s) %s（域名 %s，IP %s | %s）\n' "$_ws_i" "$_ws_n" "$(($1 + $2))" "$3" "$_ws_f"
    done <"$WORKDIR/status.idx"
    if [ "$_ws_be" = none ]; then
      printf '%s\n' "防火墙：不可用（仅拦截域名）"
    else
      printf '已生效 IP：IPv4 %s 条，IPv6 %s 条（后端：%s）\n' \
        "$(count_lines "$CFG/v4")" "$(count_lines "$CFG/v6")" "$_ws_be"
    fi
    printf '域名拦截：%s\n' "$(dns_method_text "$_ws_method")"
    printf '脚本版本：%s\n' "$VERSION"
  } >"$CFG/status.txt"
}

# 实时巡检规则状态。输出给菜单和 status 共用。
# 返回 0=正常，1=暂停，2=防火墙缺失，3=DNS 拦截异常
check_health() {
  if [ "$(cat "$CFG/enabled" 2>/dev/null)" != 1 ]; then
    return 1
  fi
  [ "$(id -u)" = 0 ] || return 0
  _ch_be=$(cat "$CFG/backend" 2>/dev/null)
  _ch_dm=$(cat "$CFG/dns.method" 2>/dev/null)
  if [ "$_ch_be" = none ]; then
    [ "$_ch_dm" = none ] && return 0
    dns_live && return 0
    return 3
  fi
  if [ -s "$CFG/v4" ] || [ -s "$CFG/v6" ] || [ "$_ch_dm" = string ]; then
    rules_live || return 2
  fi
  case $_ch_dm in
    dnsmasq|hosts)
      dns_live || return 3
      ;;
  esac
  return 0
}

show_status() {
  if [ ! -f "$CFG/status.txt" ]; then
    say_info "这台服务器还没有配置封禁名单。"
    return 0
  fi
  cat "$CFG/status.txt"
  [ "$(id -u)" = 0 ] && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ] || return 0
  check_health
  case $? in
    0) say_ok "实时检查：所有封禁规则均在正常运行" ;;
    2) say_warn "实时检查：防火墙规则缺失（可能被 UFW/firewalld 重载清掉），请运行 vps-fengjin refresh 恢复" ;;
    3) say_warn "实时检查：域名拦截未运行或系统 DNS 被重置，请运行 vps-fengjin on 恢复" ;;
  esac
}

# 主菜单顶部的精简状态面板（控制在 6 行以内，一眼看清）。
show_dashboard() {
  ui_banner
  _db_en=$(cat "$CFG/enabled" 2>/dev/null || echo 0)
  _db_be=$(cat "$CFG/backend" 2>/dev/null || echo none)
  _db_dm=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  _db_mode=$(cat "$CFG/mode" 2>/dev/null || echo all)
  _db_ports=$(cat "$CFG/ports" 2>/dev/null)
  _db_sc=$(count_sources saved)
  _db_dn=$(count_lines "$CFG/dns.list")
  _db_ip=$(( $(count_lines "$CFG/v4") + $(count_lines "$CFG/v6") ))

  if [ "$_db_en" = 1 ]; then
    check_health
    case $? in
      0) say "  运行状态：${C_GREEN}● 运行中（一切正常）${C_NC}" ;;
      2) say "  运行状态：${C_YELLOW}! 防火墙规则缺失（选 4 可立即恢复）${C_NC}" ;;
      3) say "  运行状态：${C_YELLOW}! 域名拦截异常（选 4 可立即恢复）${C_NC}" ;;
    esac
  else
    say "  运行状态：${C_YELLOW}○ 已暂停（名单已保留，选 5 随时开启）${C_NC}"
  fi
  if [ "$_db_be" = none ]; then
    say "  封禁范围：全局（仅封域名模式）"
  else
    say "  封禁范围：$(scope_text "$_db_mode" "$_db_ports")"
  fi
  say "  当前名单：${_db_sc} 份（已生效域名 ${_db_dn} 个，IP/网段 ${_db_ip} 条）"
  say "  域名方式：$(dns_method_text "$_db_dm")"
  ui_hr
}

# 实测某个域名或 IP 是否命中名单并已被拦住。
cmd_test() {
  _ct_target=$1
  if [ ! -f "$CFG/list.txt" ]; then
    say_info "还没有配置任何封禁名单，无法测试。"
    return 1
  fi
  _ct_res=$(fengjin_awk match plan="$CFG" target="$_ct_target")
  _ct_kind=$(printf '%s' "$_ct_res" | awk -F '\t' '{ print $1 }')
  _ct_val=$(printf '%s' "$_ct_res" | awk -F '\t' '{ print $2 }')
  _ct_en=$(cat "$CFG/enabled" 2>/dev/null || echo 0)
  _ct_dm=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  _ct_be=$(cat "$CFG/backend" 2>/dev/null || echo none)

  say ""
  case $_ct_kind in
    invalid)
      say_err "「${_ct_target}」不是有效的网站域名或 IP 地址。"
      return 1
      ;;
    none)
      say_warn "未命中封禁名单：「${_ct_val}」不在你已添加的规则中，当前不会被本脚本拦截。"
      return 0
      ;;
    v4|v6)
      say_ok "命中名单中的 IP 规则：$_ct_val"
      if [ "$_ct_be" = none ]; then
        say_warn "但当前机器无防火墙权限（仅封域名模式），该 IP 无法被拦截。"
        return 0
      fi
      if [ "$_ct_en" != 1 ]; then
        say_warn "当前封禁处于「已暂停」状态，不会生效。选「开启封禁」即可恢复。"
        return 0
      fi
      if rules_live; then
        say_ok "防火墙规则正在运行，该 IP 已被拦截！"
      else
        say_warn "防火墙规则当前缺失，请运行「立即重新生效」修复！"
      fi
      ;;
    domain_exact|domain_sub)
      say_ok "命中名单中的域名规则：$_ct_val"
      if [ "$_ct_en" != 1 ]; then
        say_warn "当前封禁处于「已暂停」状态，不会生效。选「开启封禁」即可恢复。"
        return 0
      fi
      _ct_host=$(printf '%s' "$_ct_target" | sed 's|^[A-Za-z][A-Za-z0-9+.-]*://||;s|[/?#].*$||;s|:[0-9]*$||' | tr 'A-Z' 'a-z')
      _ct_host=${_ct_host#\*.}; _ct_host=${_ct_host#+.}; _ct_host=${_ct_host#.}; _ct_host=${_ct_host%.}
      if [ "$_ct_dm" = hosts ]; then
        if ! awk -v h="$_ct_host" '{ for (i = 2; i <= NF; i++) if (tolower($i) == h) f = 1 } END { exit !f }' /etc/hosts 2>/dev/null; then
          say_warn "当前为 /etc/hosts 降级模式，该域名（${_ct_host}）未写入 /etc/hosts，可能无法拦截。"
          return 0
        fi
        say_dim "  正在本机实测解析 ${_ct_host}（/etc/hosts 模式）..."
        _ct_got=$(resolve_system "$_ct_host" hosts)
      else
        say_dim "  正在本机实测 DNS 解析 $_ct_host ..."
        _ct_got=$(resolve_system "$_ct_host")
      fi
      _ct_blocked=1
      for _ct_ip in $_ct_got; do
        case $_ct_ip in
          0.0.0.0|::) ;;
          *) _ct_blocked=0 ;;
        esac
      done
      if [ "$_ct_blocked" = 1 ]; then
        say_ok "实测结果：已被成功拦截！（无法解析或已指向屏蔽地址）"
      else
        say_warn "实测注意：本机仍解析到了 IP（$(printf '%s' "$_ct_got" | tr '\n' ' ')）"
        say_dim "  可能原因：规则被其他防火墙清掉 / 系统 DNS 缓存未过期 / 机器走了加密 DNS。"
        say_dim "  建议：执行「立即重新生效」后再试一次。"
      fi
      ;;
  esac
}

#----------------------------------------------------------------------
# 小白友好交互向导
#----------------------------------------------------------------------

# 处理用户在添加名单提示处直接输入的内容（链接 / 本地文件 / 域名 / IP）。
handle_direct_input() {
  _hdi_val=$(printf '%s' "$1" | sed "s/^[\"']//;s/[\"']\$//")
  case $_hdi_val in
    http://*|https://*|/*|"~/"*|./*)
      add_from "$_hdi_val"
      ;;
    *[!0-9]*)
      if [ -f "$_hdi_val" ]; then
        add_from "$_hdi_val"
      else
        add_inline "$_hdi_val"
      fi
      ;;
    *)
      say_warn "没有这个选项，请输入菜单上的数字（也可直接输入域名或粘贴网址）。"
      ;;
  esac
}

# 统一添加名单向导：支持直接输入域名/IP、粘贴网址、导入文件、批量粘贴。
# 参数 $1 = step_title（步骤标题），$2 = keep 时保留已暂存的名单（从核对页返回时用）。
# 返回 0 表示用户点击了「下一步」且至少有 1 份名单；返回 1 表示用户取消。
wizard_add_sources() {
  _wa_title=$1
  PENDING=$WORKDIR/sources
  if [ "${2:-}" != keep ]; then
    rm -rf "$PENDING"
  fi
  mkdir -p "$PENDING"
  say_step "$_wa_title"
  while :; do
    _wa_n=$(count_sources pending)
    if [ "$_wa_n" -eq 0 ]; then
      say ""
      say "请选择添加方式（域名、IP、网段可以混着写）："
      say "  1) 手动输入或批量粘贴网站 / IP ${C_GREEN}（推荐，最简单）${C_NC}"
      say "  2) 导入在线名单链接（如 GitHub / Clash / AdGuard / Hosts 规则链接）"
      say "  3) 导入服务器上的本地文件（如 /root/block.txt）"
      say "  0) 取消并返回"
      say_dim "  小技巧：也可以直接在这里输入域名（如 baidu.com）或直接粘贴网址回车！"
      ask "请输入选项，或直接输入域名 / 链接 [1]: " "1"
      case $ANSWER in
        0) return 1 ;;
        1) add_paste ;;
        2)
          ask "请粘贴在线名单链接（http/https，回车返回）：" ""
          [ -n "$ANSWER" ] && add_from "$ANSWER"
          ;;
        3)
          ask "请输入服务器文件路径（如 /root/list.txt，回车返回）：" ""
          [ -n "$ANSWER" ] && add_from "$ANSWER"
          ;;
        *) handle_direct_input "$ANSWER" ;;
      esac
    else
      merge_sources pending "$WORKDIR/pending.preview"
      summarize_list "$WORKDIR/pending.preview"
      say ""
      say "${C_BOLD}本次已添加 ${_wa_n} 份名单（共 $((N_DOMAIN + N_SUFFIX)) 个域名，${N_IP} 个 IP/网段）：${C_NC}"
      say "  1) 下一步：核对并生效 ${C_GREEN}（推荐，直接回车）${C_NC}"
      say "  2) 继续添加更多网站 / 链接 / 文件"
      say "  3) 查看、重命名或删掉刚加的名单"
      say "  0) 取消本次添加（不改动当前系统）"
      ask "请选择（也可继续直接输入域名或粘贴网址）[1]: " "1"
      case $ANSWER in
        1) return 0 ;;
        2)
          say ""
          say "  1) 手动输入或批量粘贴网站 / IP"
          say "  2) 导入在线名单链接（http/https）"
          say "  3) 导入服务器本地文件"
          say "  0) 返回"
          ask "请选择添加方式 [1]: " "1"
          case $ANSWER in
            1) add_paste ;;
            2)
              ask "请粘贴在线名单链接（回车返回）：" ""
              [ -n "$ANSWER" ] && add_from "$ANSWER"
              ;;
            3)
              ask "请输入服务器文件路径（回车返回）：" ""
              [ -n "$ANSWER" ] && add_from "$ANSWER"
              ;;
            0) ;;
            *) handle_direct_input "$ANSWER" ;;
          esac
          ;;
        3) manage_pending_sources ;;
        0)
          if ask_yn "确定放弃刚才添加的 ${_wa_n} 份名单吗？[y/N]: " n; then
            rm -rf "$PENDING"
            return 1
          fi
          ;;
        *) handle_direct_input "$ANSWER" ;;
      esac
    fi
  done
}

# 管理「本次刚加、尚未生效」的名单。
manage_pending_sources() {
  while :; do
    source_dirs pending >"$WORKDIR/pend.idx"
    if [ ! -s "$WORKDIR/pend.idx" ]; then
      say_info "本次待添加名单已清空。"
      return 0
    fi
    say ""
    say "本次已添加的名单："
    _mp_i=0
    while IFS= read -r _mp_d; do
      _mp_i=$((_mp_i + 1))
      show_source_line "$_mp_i" "$_mp_d"
    done <"$WORKDIR/pend.idx"
    ask "输入编号查看/改名/删除，直接回车返回：" ""
    [ -n "$ANSWER" ] || return 0
    _mp_d=""
    case $ANSWER in
      *[!0-9]*) ;;
      *) _mp_d=$(sed -n "${ANSWER}p" "$WORKDIR/pend.idx") ;;
    esac
    if [ -z "$_mp_d" ]; then
      say_warn "没有这个编号。"
      continue
    fi
    _mp_name=$(cat "$_mp_d/name" 2>/dev/null)
    say ""
    say "「${_mp_name}」："
    say "  1) 预览名单里的内容"
    say "  2) 修改备注名"
    say "  3) 删除这份名单"
    say "  0) 返回"
    ask_pick "请选择 [0]: " 0 1 2 3 0
    case $ANSWER in
      1) preview_source "$_mp_d" ;;
      2)
        ask "新的备注名（原名「${_mp_name}」，回车不改）：" ""
        _mp_new=$(clean_name "$ANSWER")
        if [ -n "$_mp_new" ]; then
          printf '%s\n' "$_mp_new" >"$_mp_d/name"
          say_ok "已改名为「${_mp_new}」"
        fi
        ;;
      3)
        rm -rf "$_mp_d"
        say_ok "已删除「${_mp_name}」"
        ;;
    esac
  done
}

# 高级选项：修改封禁范围。返回 0=已选，1=取消返回。
ask_scope() {
  _sc_cur_mode=${1:-all}
  _sc_cur_ports=${2:-}
  _sc_def=1
  [ "$_sc_cur_mode" = ports ] && _sc_def=2
  while :; do
    say ""
    say "请选择封禁范围："
    say "  1) 全局封禁：所有端口全部拦住 ${C_GREEN}（推荐，99% 的人选这个）${C_NC}"
    say_dim "     想让服务器和代理节点彻底打不开名单里的网站/App，就选 1。"
    say "  2) 仅封指定目标端口（高级，一般用不到）"
    say_dim "     注意：这里填的是【对方网站】的端口（例如 80,443），不是你代理节点的端口！"
    say_dim "     并且只对名单里的 IP/网段生效；域名不分端口，依然全局拦截。"
    say "  0) 返回（保持不变）"
    ask_pick "请选择 [$_sc_def]: " "$_sc_def" 1 2 0
    [ "$ANSWER" = 0 ] && return 1
    if [ "$ANSWER" = 1 ]; then
      MODE=all
      PORTS=
      return 0
    fi
    while :; do
      if [ "$_sc_cur_mode" = ports ] && [ -n "$_sc_cur_ports" ]; then
        ask "请输入要封的目标端口（逗号或空格隔开，回车沿用 ${_sc_cur_ports}，输入 0 返回）：" "$_sc_cur_ports"
      else
        ask "请输入要封的目标端口（例如 80,443，最多 30 个，输入 0 返回）：" ""
      fi
      [ "$ANSWER" = 0 ] && break
      if [ -z "$ANSWER" ]; then
        say_warn "请输入端口号，例如 443。"
        continue
      fi
      _sc_ports=$(parse_ports "$ANSWER")
      case $? in
        0)
          MODE=ports
          PORTS=$_sc_ports
          return 0
          ;;
        2) say_err "一次最多填写 30 个端口。如需封更多端口，建议直接选「全局封禁」。" ;;
        *) say_err "端口格式不对，请填写 1~65535 的数字，例如 80,443。" ;;
      esac
    done
  done
}

show_plan_summary() {
  summarize_list "$1"
  _sp_dom=$((N_DOMAIN + N_SUFFIX))
  _sp_sd=$(sample_items "$1" domain 3)
  _sp_si=$(sample_items "$1" ip 3)
  say ""
  say "${C_BOLD}即将生效的封禁配置：${C_NC}"
  if [ "$_sp_dom" -gt 0 ]; then
    say "  • 封禁域名：${_sp_dom} 个${_sp_sd:+（含 ${_sp_sd}）}"
  else
    say "  • 封禁域名：0 个"
  fi
  if [ "$FW_BACKEND" = none ]; then
    if [ "$N_IP" -gt 0 ]; then
      say "  • IP / 网段：${N_IP} 个 ${C_YELLOW}（当前受限容器无防火墙权限，IP 将跳过）${C_NC}"
    fi
    say "  • 拦截方式：仅拦截域名（含子域名），本机及代理节点均生效"
  else
    if [ "$N_IP" -gt 0 ]; then
      say "  • IP / 网段：${N_IP} 个${_sp_si:+（含 ${_sp_si}）}"
    else
      say "  • IP / 网段：0 个"
    fi
    say "  • 生效范围：$(scope_text "$MODE" "$PORTS")"
    say "  • 域名处理：仅拦截 DNS 解析（含子域名），不会误伤同 IP 的其他网站"
    say "  • 安全保护：自动跳过你的 SSH 登录 IP、本机地址和系统 DNS，不会失联"
  fi
}

# 核对并生效：给用户「生效 / 返回改名单 / 高级改范围 / 取消」完整选择。
# $1 = new|append, $2 = step_title
wizard_confirm_loop() {
  _wc_how=$1
  _wc_title=$2
  while :; do
    if [ "$_wc_how" = new ]; then
      merge_sources pending "$WORKDIR/merged.txt"
    else
      merge_sources all "$WORKDIR/merged.txt"
    fi
    say_step "$_wc_title"
    show_plan_summary "$WORKDIR/merged.txt"
    say ""
    say "  1) 确认无误，立即生效 ${C_GREEN}（推荐，直接回车）${C_NC}"
    say "  2) 返回修改刚添加的名单"
    if [ "$FW_BACKEND" != none ]; then
      say "  3) 修改封禁范围（高级，默认全局一般不用改）"
    fi
    say "  0) 取消，不做任何改动"
    ask "请选择 [1]: " "1"
    case $ANSWER in
      1|y|Y|yes|YES|是|确认)
        apply_changes "$_wc_how" "$WORKDIR/merged.txt"
        return $?
        ;;
      2)
        return 2
        ;;
      3)
        if [ "$FW_BACKEND" != none ]; then
          ask_scope "$MODE" "$PORTS" || true
        else
          say_warn "当前机器仅支持封禁域名，不支持按端口设置。"
        fi
        ;;
      0|n|N|no|NO|取消)
        rm -rf "${PENDING:-}"
        say_info "已取消，未做任何改动。"
        return 1
        ;;
      *)
        say_warn "请输入 1、2$([ "$FW_BACKEND" != none ] && echo "、3") 或 0。"
        ;;
    esac
  done
}

# 首次安装完整 2 步向导
flow_first_setup() {
  [ -n "${OS_PRETTY:-}" ] || detect_os
  _in_kb=$(mem_total_kb)
  ui_banner
  say "作用：禁止这台服务器（含上面搭建的代理节点）访问指定网站或 IP。"
  say "系统：${OS_PRETTY}  |  内存：$([ "$_in_kb" -gt 0 ] && echo "$((_in_kb / 1024)) MB" || echo 未知)"
  say ""
  say_info "正在自动检测服务器环境..."
  fw_precheck
  fw_summary_line
  MODE=all
  PORTS=
  PENDING=$WORKDIR/sources
  rm -rf "$PENDING"
  mkdir -p "$PENDING"
  while :; do
    wizard_add_sources "第 1 步 / 共 2 步：你要封禁哪些网站或 IP？" keep || {
      say_info "已退出设置，未对系统做任何改动。"
      return 1
    }
    wizard_confirm_loop new "第 2 步 / 共 2 步：核对并立即生效"
    _fs_rc=$?
    [ "$_fs_rc" -eq 2 ] && continue
    return $_fs_rc
  done
}

# 菜单 1：追加封禁
flow_append() {
  fw_precheck
  MODE=$(cat "$CFG/mode" 2>/dev/null || echo all)
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  PENDING=$WORKDIR/sources
  rm -rf "$PENDING"
  mkdir -p "$PENDING"
  while :; do
    wizard_add_sources "添加新的封禁网站 / IP / 名单" keep || return 0
    wizard_confirm_loop append "核对合并后的封禁配置"
    _fa_rc=$?
    [ "$_fa_rc" -eq 2 ] && continue
    return 0
  done
}

# 菜单 6：更换整套名单（先告知影响、可随时取消、只合并本次新加！）
flow_replace() {
  fw_precheck
  _fr_old=$(count_sources saved)
  say ""
  say_warn "注意：更换整套名单会用你接下来新加的名单，替换掉现有的 ${_fr_old} 份旧名单。"
  say_dim "  在最后一步确认之前，随时可以按 0 取消，原封禁规则不受影响。"
  ask_yn "继续更换整套名单吗？[y/N]: " n || return 0
  MODE=$(cat "$CFG/mode" 2>/dev/null || echo all)
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  [ "$MODE" = ports ] || { MODE=all; PORTS=; }
  PENDING=$WORKDIR/sources
  rm -rf "$PENDING"
  mkdir -p "$PENDING"
  while :; do
    wizard_add_sources "更换整套名单：请添加新的封禁内容" keep || return 0
    wizard_confirm_loop new "核对新名单并替换生效"
    _fr_rc=$?
    [ "$_fr_rc" -eq 2 ] && continue
    return 0
  done
}

# 重新下载某一份在线链接/本地文件名单，暂存到 $WORKDIR/upd_stage/<id>/，生效失败可完整回滚。
# 返回 0=有更新（已暂存），1=失败，2=已是最新无需更新
refresh_single_source() {
  _rs_d=$1
  _rs_id=${_rs_d##*/}
  _rs_name=$(cat "$_rs_d/name" 2>/dev/null)
  _rs_kind=$(cat "$_rs_d/kind" 2>/dev/null)
  _rs_origin=$(cat "$_rs_d/origin" 2>/dev/null)
  case $_rs_kind in
    url|file) ;;
    *)
      say_info "「${_rs_name}」是手动输入的名单，没有来源链接可更新。"
      return 1
      ;;
  esac
  say_info "正在更新「${_rs_name}」($_rs_origin)..."
  read_source "$_rs_origin" "$WORKDIR/upd.raw" || return 1
  classify_raw "$WORKDIR/upd.raw" "$WORKDIR/upd.list"
  summarize_list "$WORKDIR/upd.list"
  _rs_new_dom=$((N_DOMAIN + N_SUFFIX))
  _rs_new_ip=$N_IP
  if [ $((_rs_new_dom + _rs_new_ip)) -eq 0 ]; then
    say_err "更新后的名单为空或无法识别，已保留原名单。"
    return 1
  fi
  set -- $(cat "$_rs_d/count" 2>/dev/null) 0 0 0
  _rs_old_dom=$(($1 + $2))
  _rs_old_ip=$3
  if cmp -s "$WORKDIR/upd.list" "$_rs_d/list" 2>/dev/null; then
    say_ok "「${_rs_name}」已是最新内容（域名 $_rs_new_dom 个，IP $_rs_new_ip 个），无需变动。"
    return 2
  fi
  mkdir -p "$WORKDIR/upd_stage/$_rs_id"
  cp "$WORKDIR/upd.list" "$WORKDIR/upd_stage/$_rs_id/list"
  printf '%s %s %s\n' "$N_DOMAIN" "$N_SUFFIX" "$N_IP" >"$WORKDIR/upd_stage/$_rs_id/count"
  say_ok "「${_rs_name}」发现更新：域名 ${_rs_old_dom} → ${_rs_new_dom} 个，IP ${_rs_old_ip} → ${_rs_new_ip} 个"
  return 0
}

# 合并已保存名单，若某份名单在 upd_stage 里有更新则用更新后的版本。
merge_with_updates() {
  source_dirs saved | while IFS= read -r _mu_d; do
    _mu_id=${_mu_d##*/}
    if [ -f "$WORKDIR/upd_stage/$_mu_id/list" ]; then
      cat "$WORKDIR/upd_stage/$_mu_id/list"
    elif [ -f "$_mu_d/list" ]; then
      cat "$_mu_d/list"
    fi
  done | LC_ALL=C sort -u >"$1"
  cap_list "$1"
}

update_all_url_sources() {
  rm -rf "$WORKDIR/upd_stage"
  _ua_found=0
  _ua_changed=0
  source_dirs saved >"$WORKDIR/upd.idx"
  while IFS= read -r _ua_d; do
    [ "$(cat "$_ua_d/kind" 2>/dev/null)" = url ] || continue
    _ua_found=$((_ua_found + 1))
    refresh_single_source "$_ua_d"
    [ $? -eq 0 ] && _ua_changed=$((_ua_changed + 1))
  done <"$WORKDIR/upd.idx"
  if [ "$_ua_found" -eq 0 ]; then
    say_info "当前没有通过「在线链接」导入的名单。"
    return 0
  fi
  if [ "$_ua_changed" -eq 0 ]; then
    say_ok "全部 ${_ua_found} 份在线名单均已是最新。"
    return 0
  fi
  merge_with_updates "$WORKDIR/merged.txt"
  MODE=$(cat "$CFG/mode" 2>/dev/null || echo all)
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  apply_changes update "$WORKDIR/merged.txt"
}

# 菜单 2：查看与管理名单（预览、一键更新在线链接、改名、即刻确认删除）
flow_manage() {
  rm -rf "${PENDING:-}"
  : >"$WORKDIR/del.list"
  while :; do
    source_dirs saved >"$WORKDIR/src.idx"
    if [ ! -s "$WORKDIR/src.idx" ]; then
      say_info "目前没有任何已保存的名单。"
      return 0
    fi
    _fm_has_url=0
    say_step "已保存的封禁名单"
    _fm_i=0
    while IFS= read -r _fm_d; do
      _fm_i=$((_fm_i + 1))
      show_source_line "$_fm_i" "$_fm_d"
      [ "$(cat "$_fm_d/kind" 2>/dev/null)" = url ] && _fm_has_url=1
    done <"$WORKDIR/src.idx"
    say ""
    if [ "$_fm_has_url" = 1 ]; then
      say_dim "  输入编号可查看/更新/改名/删除某份名单；输入 u 一键更新全部在线链接；直接回车返回。"
      ask "请选择编号 / u / 回车返回：" ""
    else
      ask "输入编号查看/改名/删除某份名单，直接回车返回：" ""
    fi
    [ -n "$ANSWER" ] || return 0
    case $ANSWER in
      0) return 0 ;;
      u|U)
        if [ "$_fm_has_url" = 1 ]; then
          update_all_url_sources
          pause_enter
          continue
        fi
        ;;
    esac
    _fm_d=""
    case $ANSWER in
      *[!0-9]*) ;;
      *) _fm_d=$(sed -n "${ANSWER}p" "$WORKDIR/src.idx") ;;
    esac
    if [ -z "$_fm_d" ]; then
      say_warn "没有这个编号，请重新输入。"
      continue
    fi
    _fm_name=$(cat "$_fm_d/name" 2>/dev/null)
    _fm_kind=$(cat "$_fm_d/kind" 2>/dev/null)
    say ""
    say "${C_BOLD}操作名单「${_fm_name}」：${C_NC}"
    say "  1) 预览名单里的内容（查看前 30 条）"
    if [ "$_fm_kind" = url ] || [ "$_fm_kind" = file ]; then
      say "  2) 重新拉取并更新这份名单"
      say "  3) 修改备注名"
      say "  4) 删除这份名单"
      say "  0) 返回"
      ask_pick "请选择 [0]: " 0 1 2 3 4 0
    else
      say "  2) 修改备注名"
      say "  3) 删除这份名单"
      say "  0) 返回"
      ask_pick "请选择 [0]: " 0 1 2 3 0
      # 统一映射操作码，避免分支错乱
      case $ANSWER in
        2) ANSWER=3 ;;
        3) ANSWER=4 ;;
      esac
    fi
    case $ANSWER in
      1)
        preview_source "$_fm_d"
        pause_enter
        ;;
      2)
        rm -rf "$WORKDIR/upd_stage"
        if refresh_single_source "$_fm_d"; then
          merge_with_updates "$WORKDIR/merged.txt"
          MODE=$(cat "$CFG/mode" 2>/dev/null || echo all)
          PORTS=$(cat "$CFG/ports" 2>/dev/null)
          apply_changes update "$WORKDIR/merged.txt"
        fi
        pause_enter
        ;;
      3)
        ask "请输入新的备注名（原名「${_fm_name}」，回车不改）：" ""
        _fm_new=$(clean_name "$ANSWER")
        if [ -n "$_fm_new" ]; then
          printf '%s\n' "$_fm_new" >"$_fm_d/name"
          say_ok "已改名为「${_fm_new}」"
          [ -f "$CFG/mode" ] && write_status
        fi
        ;;
      4)
        _fm_total=$(count_sources saved)
        if [ "$_fm_total" -le 1 ]; then
          say_warn "「${_fm_name}」是最后一份名单，删除后将关闭封禁并清空所有规则。"
          if ask_yn "确定删除并清空吗？[y/N]: " n; then
            disable_all
            remove_persistence
            rm -rf "$CFG/sources" "$CFG/list.txt" "$CFG/status.txt" "$CFG/v4" "$CFG/v6" \
              "$CFG/dns.list" "$CFG/resolved.last" "$CFG/mode" "$CFG/ports" \
              "$CFG/backend" "$CFG/dns.method" "$CFG/v4.active" "$CFG/v6.active"
            printf '%s\n' 0 >"$CFG/enabled"
            say_ok "已清空所有名单并关闭封禁。随时运行 vps-fengjin 可重新设置。"
            exit 0
          fi
        else
          if ask_yn "确定删除「${_fm_name}」并立即用剩余名单重新生效吗？[y/N]: " n; then
            printf '%s\n' "$_fm_d" >"$WORKDIR/del.list"
            merge_sources all "$WORKDIR/merged.txt"
            MODE=$(cat "$CFG/mode" 2>/dev/null || echo all)
            PORTS=$(cat "$CFG/ports" 2>/dev/null)
            apply_changes delete "$WORKDIR/merged.txt"
            pause_enter
          fi
        fi
        ;;
    esac
  done
}

# 菜单 3：测试某个网站或 IP 是否已被封住
flow_test() {
  say_step "测试某个网站或 IP 是否已被封住"
  say_dim "  输入要检查的域名或 IP（如 baidu.com、https://www.qq.com、1.2.3.4），直接回车返回。"
  while :; do
    ask "请输入要测试的目标（回车返回）：" ""
    [ -n "$ANSWER" ] || return 0
    cmd_test "$ANSWER"
    say ""
  done
}

# 菜单 7：高级设置（修改封禁范围）
flow_scope() {
  fw_precheck
  if [ "$FW_BACKEND" = none ]; then
    say ""
    say_info "当前机器没有修改防火墙权限，只能全局封禁域名，无法按端口设置。"
    return 0
  fi
  _fs_cur_m=$(cat "$CFG/mode" 2>/dev/null || echo all)
  _fs_cur_p=$(cat "$CFG/ports" 2>/dev/null)
  ask_scope "$_fs_cur_m" "$_fs_cur_p" || return 0
  show_plan_summary "$CFG/list.txt"
  if ask_yn "确认应用新的封禁范围吗？[Y/n]: " y; then
    apply_changes keep ""
  else
    say_info "已取消，未作改动。"
  fi
}

flow_reapply() {
  MODE=$(cat "$CFG/mode" 2>/dev/null || echo all)
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  apply_changes keep ""
}

cmd_off() {
  if [ ! -d "$CFG" ]; then
    say_info "这台服务器还没有配置封禁。"
    return 0
  fi
  printf '%s\n' 0 >"$CFG/enabled"
  disable_all
  [ -f "$CFG/list.txt" ] && write_status
  say_ok "已暂停封禁，所有名单均已保留。随时运行 vps-fengjin on 或在菜单中即可重新开启。"
}

cmd_purge() {
  disable_all
  remove_persistence
  if [ -f /swapfile-vps-fengjin ]; then
    swapoff /swapfile-vps-fengjin 2>/dev/null
    rm -f /swapfile-vps-fengjin
    if grep -q '/swapfile-vps-fengjin' /etc/fstab 2>/dev/null; then
      grep -v '/swapfile-vps-fengjin' /etc/fstab >"$WORKDIR/fstab.new"
      cat "$WORKDIR/fstab.new" >/etc/fstab
    fi
  fi
  rm -rf "$CFG"
  rm -f "$BIN_DEFAULT" "$BIN_LINK" /usr/sbin/vps-fengjin
  say_ok "已彻底卸载：所有封禁规则、名单、开机自启与快捷命令均已清理干净。"
}

menu() {
  while :; do
    show_dashboard
    _mn_en=$(cat "$CFG/enabled" 2>/dev/null || echo 0)
    say "  1) 添加封禁（输入域名 / IP、导入链接或文件）"
    say "  2) 查看与管理名单（预览内容 / 更新在线链接 / 改名 / 删除）"
    say "  3) 测试某个网站或 IP 是否已被封住"
    say "  4) 立即重新生效 / 刷新规则"
    if [ "$_mn_en" = 1 ]; then
      say "  5) 暂停封禁（保留名单，随时可恢复）"
    else
      say "  5) ${C_GREEN}开启封禁（立即按已存名单生效）${C_NC}"
    fi
    say "  6) 更换整套名单（清空旧名单并重新添加）"
    say "  7) 高级设置（修改封禁范围：全局 / 指定目标端口）"
    say "  8) 彻底卸载（清除所有规则、名单与自启）"
    say "  0) 退出"
    ui_hr
    ask_pick "请选择功能 [0]: " 0 1 2 3 4 5 6 7 8 0
    case $ANSWER in
      1) flow_append; pause_enter ;;
      2) flow_manage ;;
      3) flow_test ;;
      4) flow_reapply; pause_enter ;;
      5)
        if [ "$_mn_en" = 1 ]; then
          cmd_off
        else
          flow_reapply
        fi
        pause_enter
        ;;
      6) flow_replace; pause_enter ;;
      7) flow_scope; pause_enter ;;
      8)
        say ""
        say_warn "彻底卸载会清除所有封禁规则、已保存名单、定时巡检和 vps-fengjin 命令。"
        if ask_yn "确定要彻底卸载吗？[y/N]: " n; then
          cmd_purge
          return 0
        fi
        say_info "已取消卸载。"
        pause_enter
        ;;
      0) return 0 ;;
    esac
  done
}

#----------------------------------------------------------------------
# 非交互参数模式：sh install.sh -l 名单 [-p 端口 | -a] [--replace] -y
#----------------------------------------------------------------------

confirm_cli() {
  [ "${OPT_YES:-0}" = 1 ] && return 0
  if ask_yn "确认立即生效？[y/N]: " n; then
    return 0
  fi
  say_info "已取消，未做任何改动。"
  return 1
}

unattended() {
  if [ "${OPT_REPLACE:-0}" = 1 ] && [ ! -s "$WORKDIR/opt.lists" ]; then
    die "使用 --replace 时必须同时用 -l 指定新名单。"
  fi
  if [ -s "$WORKDIR/opt.lists" ]; then
    PENDING=$WORKDIR/sources
    rm -rf "$PENDING"
    mkdir -p "$PENDING"
    while IFS= read -r _un_src; do
      add_from "$_un_src" || die "名单「${_un_src}」导入失败，已中止，未做任何改动。"
    done <"$WORKDIR/opt.lists"
    _un_how=append
    if [ ! -f "$CFG/list.txt" ] || [ "${OPT_REPLACE:-0}" = 1 ]; then
      _un_how=new
    fi
  else
    [ -f "$CFG/list.txt" ] || die "还没有名单。请用 -l 指定名单网址或文件，例如：sh install.sh -l https://example.com/list.txt -y"
    _un_how=keep
  fi
  if [ "$_un_how" = new ]; then
    merge_sources pending "$WORKDIR/merged.txt"
  elif [ "$_un_how" = append ]; then
    merge_sources all "$WORKDIR/merged.txt"
  else
    cp "$CFG/list.txt" "$WORKDIR/merged.txt"
  fi
  MODE=${OPT_MODE:-$(cat "$CFG/mode" 2>/dev/null)}
  [ -n "$MODE" ] || MODE=all
  if [ "$MODE" = ports ]; then
    PORTS=${OPT_PORTS:-$(cat "$CFG/ports" 2>/dev/null)}
    [ -n "$PORTS" ] || die "按端口封禁必须用 -p 指定端口，例如 -p 80,443。"
  else
    PORTS=
  fi
  fw_precheck
  show_plan_summary "$WORKDIR/merged.txt"
  confirm_cli || exit 0
  if [ "$_un_how" = keep ]; then
    apply_changes keep ""
  else
    apply_changes "$_un_how" "$WORKDIR/merged.txt"
  fi
}

parse_opts() {
  : >"$WORKDIR/opt.lists"
  OPT_GIVEN=0
  OPT_REPLACE=0
  OPT_YES=0
  OPT_MODE=
  OPT_PORTS=
  while [ $# -gt 0 ]; do
    case $1 in
      -l|--list)
        [ $# -ge 2 ] || die "$1 后面需要跟名单链接或文件路径。"
        printf '%s\n' "$2" >>"$WORKDIR/opt.lists"
        shift 2
        ;;
      --list=*)
        printf '%s\n' "${1#--list=}" >>"$WORKDIR/opt.lists"
        shift
        ;;
      -p|--ports)
        [ $# -ge 2 ] || die "$1 后面需要跟端口号，例如 80,443。"
        OPT_PORTS=$(parse_ports "$2") || die "端口格式不对：${2}（1~65535，最多 30 个）"
        OPT_MODE=ports
        shift 2
        ;;
      --ports=*)
        OPT_PORTS=$(parse_ports "${1#--ports=}") || die "端口格式不对：${1#--ports=}"
        OPT_MODE=ports
        shift
        ;;
      -a|--all)
        OPT_MODE=all
        shift
        ;;
      --replace)
        OPT_REPLACE=1
        shift
        ;;
      -y|--yes)
        OPT_YES=1
        shift
        ;;
      *)
        usage >&2
        exit 1
        ;;
    esac
    OPT_GIVEN=1
  done
}

usage() {
  cat <<EOF
用法：
  vps-fengjin                       首次进入引导设置；已设置则打开管理菜单
  vps-fengjin [选项]                 不进菜单，直接用参数设置
  vps-fengjin status                查看当前状态与规则健康检查
  vps-fengjin test 域名或IP          测试某个网站或 IP 是否已被封住
  vps-fengjin update-lists          重新下载所有在线链接名单并生效
  vps-fengjin refresh               按保存的名单重新封一次
  vps-fengjin on | off              开启 / 暂停封禁（名单保留）
  vps-fengjin purge                 彻底卸载
  vps-fengjin check 文件或网址       仅检查名单内容，不修改防火墙

选项：
  -l, --list 名单    名单链接或本地文件路径，可多次指定；写 - 表示从标准输入读
  -a, --all          全局封禁（默认）
  -p, --ports 端口   仅封指定目标端口，例如 80,443（高级，仅对 IP/网段生效）
      --replace      替换掉原有全部名单（默认是追加）
  -y, --yes          跳过确认，直接生效

示例：
  sh install.sh -l https://example.com/block.list -y
  sh install.sh -l /root/a.txt -l /root/b.txt --replace -y
EOF
}

#----------------------------------------------------------------------
# 锁管理与入口
#----------------------------------------------------------------------

require_root() {
  [ "$(id -u)" = 0 ] || die "请使用 root 权限运行，例如：sudo sh install.sh"
}

require_linux() {
  [ "$(uname -s)" = Linux ] || die "此脚本只能在 Linux 服务器上运行。"
}

proc_start() {
  sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk 'NR == 1 { print $20 }'
}

lock_alive() {
  LOCK_PID=$(sed -n 1p "$LOCKDIR/pid" 2>/dev/null | tr -cd '0-9')
  LOCK_CMD=$(sed -n 1p "$LOCKDIR/cmd" 2>/dev/null)
  [ -n "$LOCK_PID" ] || return 1
  kill -0 "$LOCK_PID" 2>/dev/null || return 1
  _la_now=$(proc_start "$LOCK_PID")
  LOCK_SURE=0
  [ -n "$_la_now" ] || return 0
  LOCK_SURE=1
  _la_then=$(sed -n 1p "$LOCKDIR/start" 2>/dev/null)
  if [ -n "$_la_then" ]; then
    [ "$_la_then" = "$_la_now" ]
    return
  fi
  case $(tr '\000' ' ' <"/proc/$LOCK_PID/cmdline" 2>/dev/null) in
    *fengjin*|*install.sh*) return 0 ;;
  esac
  return 1
}

LOCK_BASES="/run /tmp"
take_lock() {
  LOCKED=0
  for _tl_base in $LOCK_BASES; do
    [ -d "$_tl_base" ] || continue
    LOCKDIR=$_tl_base/vps-fengjin.lock
    for _tl in 1 2; do
      if mkdir "$LOCKDIR" 2>/dev/null; then
        if echo $$ 2>/dev/null >"$LOCKDIR/pid"; then
          proc_start $$ >"$LOCKDIR/start" 2>/dev/null
          printf '%s\n' "${1:-setup}" >"$LOCKDIR/cmd" 2>/dev/null
          LOCKED=1
          return 0
        fi
        rm -rf "$LOCKDIR" 2>/dev/null
        break
      fi
      [ -d "$LOCKDIR" ] || break
      [ -s "$LOCKDIR/pid" ] || sleep 1
      lock_alive && return 1
      rm -rf "$LOCKDIR" 2>/dev/null
      [ -d "$LOCKDIR" ] && break
    done
  done
  LOCKDIR=
  return 0
}

take_lock_or_die() {
  _tw=0
  _tk=0
  while ! take_lock "$1"; do
    case ${LOCK_CMD:-} in
      refresh|apply|apply-rules)
        if [ "$_tw" -lt "${LOCK_WAIT:-180}" ]; then
          [ "$_tw" = 0 ] && say_info "后台定时巡检正在运行（进程 ${LOCK_PID}），等待完成..."
          sleep 2
          _tw=$((_tw + 2))
          continue
        fi
        ;;
    esac
    _tk=$((_tk + 1))
    if [ "$_tk" -gt 3 ]; then
      LOCKED=0
      LOCKDIR=
      return 0
    fi
    if [ "${LOCK_SURE:-0}" = 1 ]; then
      say_warn "检测到另一个窗口正在运行 vps-fengjin（进程 ${LOCK_PID}），已自动接管。"
      kill "$LOCK_PID" 2>/dev/null
      for _ti in 1 2 3 4 5 6; do
        kill -0 "$LOCK_PID" 2>/dev/null || break
        sleep 0.5 2>/dev/null || sleep 1
      done
      kill -9 "$LOCK_PID" 2>/dev/null
    else
      say_warn "发现残留锁文件，已自动接管继续运行。"
    fi
    [ -n "${LOCKDIR:-}" ] && rm -rf "$LOCKDIR" 2>/dev/null
  done
}

cleanup() {
  [ -n "${WORKDIR:-}" ] && [ "$WORKDIR" != / ] && rm -rf "$WORKDIR"
  if [ "${LOCKED:-0}" = 1 ] && [ -n "${LOCKDIR:-}" ] && [ "$(cat "$LOCKDIR/pid" 2>/dev/null)" = "$$" ]; then
    rm -rf "$LOCKDIR"
  fi
}

make_workdir() {
  umask 022
  WORKDIR=$(mktemp -d "$(pick_tmpdir)/vps-fengjin.XXXXXX" 2>/dev/null)
  if [ -z "$WORKDIR" ] || [ ! -d "$WORKDIR" ]; then
    WORKDIR=/tmp/vps-fengjin.$$
    mkdir -p "$WORKDIR" || exit 1
  fi
  LOCKED=0
  trap cleanup EXIT
  trap 'exit 130' INT TERM HUP
}

prepare_setup() {
  require_linux
  require_root
  take_lock_or_die setup
  detect_os
  _pr_old=$(sed -n 's/^VERSION=//p' "$(installed_bin)" 2>/dev/null | head -n 1)
  install_self
  UPGRADED=0
  if [ -n "$_pr_old" ] && [ "$_pr_old" != "$VERSION" ]; then
    say_ok "脚本已从 v$_pr_old 更新到 v${VERSION}（原有配置和名单完整保留）"
    UPGRADED=1
  fi
  migrate_sources
  if [ "${UPGRADED:-0}" != 1 ] && [ -f "$CFG/mode" ] && [ -f "$CFG/list.txt" ]; then
    write_status
  fi
}

main() {
  save_stdin
  make_workdir
  case ${1:-} in
    -h|--help|help)
      usage
      ;;
    -V|--version|version)
      printf '%s\n' "$VERSION"
      ;;
    status)
      show_status
      [ -f "$CFG/status.txt" ] && say "" && say_dim "管理菜单：vps-fengjin  |  测试拦截：vps-fengjin test baidu.com  |  暂停：vps-fengjin off"
      ;;
    test)
      [ -n "${2:-}" ] || die "用法：vps-fengjin test 域名或IP（例如：vps-fengjin test baidu.com）"
      cmd_test "$2"
      ;;
    check)
      [ -n "${2:-}" ] || die "用法：vps-fengjin check 名单文件或网址"
      read_source "$2" "$WORKDIR/check.raw" || exit 1
      fengjin_awk classify <"$WORKDIR/check.raw" >"$WORKDIR/check.all"
      summarize_list "$WORKDIR/check.all"
      say_ok "解析结果：有效域名 $((N_DOMAIN + N_SUFFIX)) 个，IP / 网段 $N_IP 个，跳过 $N_BAD 行"
      show_bads "$WORKDIR/check.all"
      ;;
    update-lists)
      require_linux
      require_root
      [ -f "$CFG/list.txt" ] || die "还没有配置封禁名单。"
      take_lock_or_die update
      detect_os
      migrate_sources
      update_all_url_sources
      ;;
    apply-rules)
      require_linux
      require_root
      [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ] || exit 0
      take_lock apply-rules || exit 0
      detect_os
      load_rules 0
      ;;
    refresh|apply)
      require_linux
      require_root
      [ -f "$CFG/list.txt" ] || die "还没有配置封禁名单。"
      if [ "$(cat "$CFG/enabled" 2>/dev/null)" != 1 ]; then
        say_info "封禁当前处于暂停状态，未刷新。"
        exit 0
      fi
      take_lock refresh || { say_warn "另一个 vps-fengjin 任务正在运行，本次跳过。"; exit 0; }
      detect_os
      activate refresh
      say_ok "规则已刷新：域名 $(count_lines "$CFG/dns.list") 个，IPv4 $(count_lines "$CFG/v4") 条，IPv6 $(count_lines "$CFG/v6") 条。"
      ;;
    on)
      require_linux
      require_root
      [ -f "$CFG/list.txt" ] || die "还没有配置名单，请直接运行 vps-fengjin 开始设置。"
      take_lock_or_die on
      detect_os
      flow_reapply || exit 1
      ;;
    off)
      require_linux
      require_root
      take_lock_or_die off
      cmd_off
      ;;
    purge)
      require_linux
      require_root
      take_lock_or_die purge
      cmd_purge
      ;;
    ''|-*)
      parse_opts "$@"
      prepare_setup
      if [ "$OPT_GIVEN" = 1 ]; then
        unattended
      elif [ -f "$CFG/list.txt" ] && [ -f "$CFG/mode" ]; then
        if [ "${UPGRADED:-0}" = 1 ] && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
          if ask_yn "检测到版本升级，是否立刻用新版本规则重新生效一次？[Y/n]: " y; then
            flow_reapply
          else
            write_status
          fi
        fi
        menu
      else
        if flow_first_setup && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
          say ""
          say_dim "以后随时输入 vps-fengjin 打开管理菜单，或输入 vps-fengjin test baidu.com 验证拦截效果。"
        fi
      fi
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

if [ "${VPS_FENGJIN_LIB:-}" != 1 ]; then
  main "$@"
fi
