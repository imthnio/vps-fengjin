#!/bin/sh
# vps-fengjin-onekey-begin
#======================================================================
# 封禁一台服务器访问指定的域名、IP、网段。
#
# 第一次运行会一步步问：名单从哪来、封整台机器还是只封某些目标端口、确认。
# 以后再运行是菜单：重新生效、追加、管理名单、换名单、改范围、关闭、删除。
# 也可以不提问，直接用参数跑完（适合批量部署）：
#
#   sh install.sh                          按提示设置 / 打开菜单
#   sh install.sh -l 名单网址或文件 -y        整台机器封，不提问
#   sh install.sh -l 名单 -p 80,443 -y      只封这些目标端口，不提问
#   sh install.sh status                   查看
#   sh install.sh refresh                  域名重新解析后再封一次
#   sh install.sh apply-rules              只按保存的结果封，不重新解析（开机用）
#   sh install.sh on | off                 打开 / 关闭，名单留着
#   sh install.sh purge                    彻底删除
#   sh install.sh check 文件                只检查名单，不改防火墙
#
# 64MB 内存的小鸡也能跑：不装大软件，临时文件放硬盘，解析域名的并发按内存定。
#======================================================================

VERSION=2.1.0
CFG=/etc/vps-fengjin
CHAIN=VPS_FENGJIN
SET4=vps_fengjin4
SET6=vps_fengjin6
NFT_TABLE=vpsfengjin
BIN_DEFAULT=/usr/local/sbin/vps-fengjin

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

if [ -t 1 ]; then
  C_RED=$(printf '\033[0;31m')
  C_GREEN=$(printf '\033[0;32m')
  C_YELLOW=$(printf '\033[1;33m')
  C_BLUE=$(printf '\033[0;34m')
  C_NC=$(printf '\033[0m')
else
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_NC=''
fi

say()      { printf '%s\n' "$*"; }
say_ok()   { printf '%s\n' "${C_GREEN}✓ $*${C_NC}"; }
say_info() { printf '%s\n' "${C_BLUE}$*${C_NC}"; }
say_warn() { printf '%s\n' "${C_YELLOW}! $*${C_NC}"; }
say_err()  { printf '%s\n' "${C_RED}✗ $*${C_NC}" >&2; }
say_step() { printf '\n%s\n' "${C_YELLOW}>>> $*${C_NC}"; }
die()      { say_err "$*"; exit 1; }

# 数文件里的非空行。文件不存在算 0。
count_lines() {
  if [ -f "$1" ]; then
    awk 'NF { c++ } END { print c + 0 }' "$1"
  else
    printf '%s\n' 0
  fi
}

#----------------------------------------------------------------------
# 纯判断。测试直接调用，不改系统。
#   fengjin_awk 模式 [名字=值 ...]
# 模式：classify / ports / wire / extract / overlap / rules / ipset / nft
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
    split(net, a, "/")
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
    split(net, a, "/")
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
  # 压缩成常见写法：去掉前导 0，最长的一段全 0 写成 ::
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
  # 顶级域不会是纯数字。hosts 名单里的 "0.0.0.0 0.0.0.0" 这类行不能当域名。
  return lab[n] !~ /^[0-9]+$/
}
function is_sink(s) {
  return s == "0.0.0.0" || s == "127.0.0.1" || s == "::" || s == "::1" || s == "255.255.255.255"
}
function emit_name(kind, host) {
  host = tolower(trim(host))
  sub(/\.$/, "", host)
  if (substr(host, 1, 2) == "*." || substr(host, 1, 2) == "+.") {
    # +.example.com 是 Clash 的写法，和 *.example.com 一样表示本域名和所有子域名。
    kind = "suffix"
    host = substr(host, 3)
  } else if (substr(host, 1, 1) == ".") {
    kind = "suffix"
    host = substr(host, 2)
  }
  # 有的名单把 IP 写在域名位置，例如 DOMAIN-SUFFIX,1.2.3.4。按 IP 封。
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
    split(s, a, "/")
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
      # 把主机位清零。nft 的区间集合不接受带主机位的网段。
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
function emit_addr_or_name(s,   n, f, i, host) {
  n = split(s, f, /[ \t]+/)
  if (n >= 2 && is_sink(f[1])) {
    for (i = 2; i <= n; i++) emit_name("domain", f[i])
    return
  }
  if (n >= 2) {
    bad("parse", s)
    return
  }
  if (s ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", s)
  if (is_ipv4(s) || is_ipv6(s) || index(s, "/") > 0) {
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
function do_classify(   s, f, kind, host) {
  s = $0
  # 文件开头可能带 UTF-8 的 BOM（看不见的标记），会让第一行认不出来。
  sub(/^\357\273\277/, "", s)
  s = trim(s)
  if (s == "" || substr(s, 1, 1) == "#" || substr(s, 1, 1) == "!") return
  if (substr(s, 1, 2) == "@@") return
  sub(/[ \t]+#.*/, "", s)
  s = trim(s)
  if (s == "") return
  # Clash 的 YAML 名单：第一行 payload:，后面每行是 - 加一条规则，规则可以带引号。
  if (s ~ /^payload:[ \t]*$/) return
  if (s ~ /^-[ \t]+/) {
    sub(/^-[ \t]+/, "", s)
    s = trim(s)
  }
  if (length(s) >= 2 && s ~ /^[\047"].*[\047"]$/) s = trim(substr(s, 2, length(s) - 2))
  if (s == "") return
  # 全角逗号写成的规则，例如 DOMAIN，example.com
  if (s ~ /^[A-Za-z0-9_-]+[ \t]*，/) gsub(/[ \t]*，[ \t]*/, ",", s)
  if (s ~ /^address=\//) {
    split(s, f, "/")
    emit_name("suffix", f[2])
    return
  }
  if (s ~ /^\|\|/) {
    sub(/^\|\|/, "", s)
    sub(/\^.*$/, "", s)
    emit_name("suffix", s)
    return
  }
  if (index(s, ",") > 0) {
    split(s, f, ",")
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
    if (kind ~ /^[A-Z0-9_-]+$/) { bad("unsupported", s); return }
  }
  s = strip_url(s)
  if (substr(s, 1, 1) == "[" && match(s, /^\[[0-9A-Fa-f:]+\]/)) {
    emit_addr(substr(s, 2, RLENGTH - 2))
    return
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
# 解析结果里挑出 IP。dig 的问题行（分号开头）和自己写的 @@@ 行标出是哪个域名，
# 用来数解析成功了几个域名。DNS 服务器自己的地址、本机和特殊地址都不要。
function emit_ip(s) {
  gsub(/^[\[\(]+/, "", s)
  gsub(/[\]\)\.,;]+$/, "", s)
  if (s ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", s)
  if (s ~ /#[0-9]+$/) sub(/#[0-9]+$/, "", s)
  if (is_ipv4(s)) {
    if (s == server || v4_special(s)) return 0
  } else if (is_ipv6(s)) {
    s = tolower(s)
    if (s == server || v6_special(s)) return 0
  } else return 0
  if (!(s in seenip)) {
    seenip[s] = 1
    print s
  }
  return 1
}
function set_current(s) {
  s = tolower(s)
  sub(/\.$/, "", s)
  cur = s
}
function do_extract(   n, i, f, hit) {
  if (substr($0, 1, 4) == "@@@ ") { set_current(substr($0, 5)); return }
  if (substr($0, 1, 2) == ";;") return
  if (substr($0, 1, 1) == ";") {
    split(substr($0, 2), f, /[ \t]+/)
    set_current(f[1])
    return
  }
  n = split($0, f, /[ \t]+/)
  hit = 0
  for (i = 1; i <= n; i++) if (emit_ip(f[i])) hit = 1
  if (hit && cur != lastok) {
    okn++
    lastok = cur
  }
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
function emit_match(mspec, mode_s, ports_s,   n, i, p, group, count) {
  if (mode_s == "all") {
    # TCP 回 reset，对方程序立刻知道连不上，不用干等超时。
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
function render_rules(   mode_s, ports_s, method, list, setname, addr, line, h, c, opt) {
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
  if (mode_s != "all" || method != "string" || nodns == "1" || algo == "") return
  # 拦 53 端口上的域名查询。末尾带上 00 结束符：example.com 不会误拦 example.com.cn，
  # 子域名照样拦。--icase 防止大小写混写的查询（0x20 随机大小写）绕过去。
  opt = " --algo " algo (icase == "1" ? " --icase" : "")
  while ((getline line < (plan "/dns.list")) > 0) {
    h = wire_hex(line)
    if (h == "" || length(h) > 240) continue
    rule("-p udp --dport 53 -m string --hex-string |" h "00|" opt " -j " oth_jump())
    rule("-p tcp --dport 53 -m string --hex-string |" h "00|" opt " -j " tcp_jump())
  }
  close(plan "/dns.list")
}
# 先装进临时集合，外面再和正式集合对调。换的过程中旧集合一直有效。
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
  print "    auto-merge"
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
    print "    " target " meta l4proto tcp reject with tcp reset"
    print "    " target " reject"
    return
  }
  ports = ports_s
  gsub(/,/, ", ", ports)
  print "    " target " tcp dport { " ports " } reject with tcp reset"
  print "    " target " udp dport { " ports " } reject"
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
  if (set4 == "") set4 = "vps_fengjin4"
  if (set6 == "") set6 = "vps_fengjin6"
  if (table == "") table = "vpsfengjin"
  if (cap == "") cap = 1500
  lastok = "\001"
  if (mode == "rules") { render_rules(); exit }
  if (mode == "ipset") { render_ipset(); exit }
  if (mode == "nft") { render_nft(); exit }
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
  else if (mode == "extract") do_extract()
  else if (mode == "overlap") do_overlap()
}
END {
  if (mode == "extract" && okfile != "") print okn + 0 > okfile
}
'

fengjin_awk() {
  _fa_mode=$1
  shift
  _fa_n=$#
  # 把 名字=值 变成 awk 的 -v 名字=值
  for _fa_arg in "$@"; do
    set -- "$@" -v "$_fa_arg"
  done
  shift "$_fa_n"
  LC_ALL=C awk -v mode="$_fa_mode" "$@" "$FENGJIN_AWK"
}

# 返回 0 时打印整理好的端口；1 表示写错，2 表示超过 30 个。
parse_ports() {
  printf '%s\n' "$1" | fengjin_awk ports
}

#----------------------------------------------------------------------
# 提问。
# 所有回答都从 3 号描述符读：stdin 是键盘就读 stdin；不是（例如 curl ... | sh）
# 就读 /dev/tty；连终端都没有（例如自动化脚本 printf '答案' | sh install.sh），
# 再回到 stdin。提示语写到 stderr，不会混进 $(...) 拿到的结果里。
#----------------------------------------------------------------------

# 原来的 stdin 存到 4 号描述符。函数可能在 while ... done <文件 里被调用，
# 那时的 0 号已经不是原来的 stdin 了。
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

# ask 提示 [默认值]。结果放在 ANSWER，已去掉首尾空白和 Windows 换行。
ask() {
  input_init
  printf '%s' "$1" >&2
  if ! IFS= read -r ANSWER <&3; then
    printf '\n' >&2
    die "没有读到输入。不想一问一答的话，可以用参数运行，例如：vps-fengjin -l 名单网址 -y"
  fi
  # 答案不是从键盘来的，就回显一下，日志里能看出每一步选了什么。
  [ "$IN_TTY" = 1 ] || printf '%s\n' "$ANSWER" >&2
  ANSWER=$(printf '%s' "$ANSWER" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -n "$ANSWER" ] || ANSWER=${2:-}
}

# ask_yn 提示 默认(y/n)。是返回 0，否返回 1。
ask_yn() {
  while :; do
    ask "$1" "$2"
    case $ANSWER in
      y|Y|yes|Yes|YES|是|好|确认) return 0 ;;
      n|N|no|No|NO|否|不) return 1 ;;
    esac
    say_warn "请输入 y 或 n。"
  done
}

# ask_pick 提示 默认 可选值...。ANSWER 一定是可选值之一。
ask_pick() {
  _ap_prompt=$1
  _ap_def=$2
  shift 2
  while :; do
    ask "$_ap_prompt" "$_ap_def"
    for _ap_c in "$@"; do
      [ "$ANSWER" = "$_ap_c" ] && return 0
    done
    say_warn "请输入 $(printf '%s ' "$@" | sed 's/ $//;s/ /、/g') 中的一个。"
  done
}

#----------------------------------------------------------------------
# 系统、内存、软件源
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

# 名单上限。真正吃内存的是 dnsmasq 里的域名，每条大约一百字节。
# 64MB 小鸡放 10 万条，大一些的机器可以吃下整份去广告名单。
list_limits() {
  LIST_MAX_MB=32
  LIST_MAX_BYTES=$((LIST_MAX_MB * 1048576))
  if [ "$(mem_total_kb)" -gt 196608 ]; then
    LIST_MAX_ITEMS=500000
  else
    LIST_MAX_ITEMS=100000
  fi
}

# 没有 ipset 时，地址得一条条写进 iptables，条数一多匹配变慢。按内存给上限。
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

# 同时解析域名的进程数。每个 dig 要占几 MB 内存，小鸡只开几个。
resolve_workers() {
  _kb=$(mem_total_kb)
  if [ "$_kb" -eq 0 ] || [ "$_kb" -le 131072 ]; then
    printf '%s\n' 4
  elif [ "$_kb" -le 524288 ]; then
    printf '%s\n' 8
  else
    printf '%s\n' 16
  fi
}

# 临时目录尽量放硬盘。很多系统的 /tmp 是内存盘，几 MB 的名单复制几份就能把小鸡挤爆。
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
  say_info "内存大约 $((_kb / 1024)) MB。按小鸡处理：允许内存超卖，磁盘够的话加 64MB 交换。"
  sysctl -w vm.overcommit_memory=1 >/dev/null 2>&1 || true
  if awk 'NR > 1 { found = 1 } END { exit found ? 0 : 1 }' /proc/swaps 2>/dev/null; then
    return 0
  fi
  _free=$(df -Pk / 2>/dev/null | awk 'NR == 2 { print $4 }')
  case ${_free:-} in
    ''|*[!0-9]*) _free=0 ;;
  esac
  if [ "$_free" -ge 180000 ]; then
    make_swap || say_warn "交换空间没加上，继续。名单特别大时可能会紧。"
  else
    say_warn "磁盘剩余不多，不加交换空间。"
  fi
}

make_swap() {
  _f=/swapfile-vps-fengjin
  if [ -f "$_f" ]; then
    grep -q "$_f" /proc/swaps 2>/dev/null && return 0
    swapon "$_f" 2>/dev/null && return 0
    rm -f "$_f"
  fi
  if ! { command -v fallocate >/dev/null 2>&1 && fallocate -l 64M "$_f" 2>/dev/null; }; then
    dd if=/dev/zero of="$_f" bs=1048576 count=64 >/dev/null 2>&1 || { rm -f "$_f"; return 1; }
  fi
  # 容器里常常不让开交换。失败就把文件删掉，别在小硬盘上留 64MB 垃圾。
  if ! chmod 600 "$_f" || ! mkswap "$_f" >/dev/null 2>&1 || ! swapon "$_f" 2>/dev/null; then
    rm -f "$_f"
    return 1
  fi
  if ! grep -q "$_f" /etc/fstab 2>/dev/null; then
    printf '%s none swap sw 0 0\n' "$_f" >>/etc/fstab
  fi
  say_ok "已加上 64MB 交换空间"
}

# 安装输出写进 pm.log，装失败时给用户看最后几行，不再一声不吭。
pm_install() {
  _pm_log=${WORKDIR:-/tmp}/pm.log
  case ${PM:-none} in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      if [ "${APT_UPDATED:-0}" != 1 ]; then
        apt-get update -qq >>"$_pm_log" 2>&1 || say_warn "软件源没有完全更新，仍尝试安装。"
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
        opkg update >>"$_pm_log" 2>&1 || say_warn "opkg 源更新失败，仍尝试安装。"
        OPKG_UPDATED=1
      fi
      opkg install "$1" >>"$_pm_log" 2>&1
      ;;
    *) return 1 ;;
  esac
}

# need_cmd 命令 软件包...：缺命令时按顺序试装这些包，装上一个就停。
need_cmd() {
  _nc_cmd=$1
  shift
  command -v "$_nc_cmd" >/dev/null 2>&1 && return 0
  for _nc_pkg in "$@"; do
    say_info "缺少 $_nc_cmd，尝试安装 $_nc_pkg"
    : >"${WORKDIR:-/tmp}/pm.log"
    if pm_install "$_nc_pkg" && command -v "$_nc_cmd" >/dev/null 2>&1; then
      say_ok "已装上 $_nc_pkg"
      return 0
    fi
  done
  say_warn "$_nc_cmd 没装上。安装输出的最后几行："
  tail -n 3 "${WORKDIR:-/tmp}/pm.log" 2>/dev/null | sed 's/^/    /'
  return 1
}

#----------------------------------------------------------------------
# 防火墙探测。只拦本机发出去的连接（OUTPUT）。代理程序替用户连出去，也算本机发出。
#----------------------------------------------------------------------

# ipt_try 程序 规则...：在测试链里试加一条规则，返回能不能加上。
ipt_try() {
  _it_bin=$1
  shift
  "$_it_bin" -A VPS_FENGJIN_T "$@" >/dev/null 2>&1
  _it_rc=$?
  "$_it_bin" -F VPS_FENGJIN_T >/dev/null 2>&1
  return $_it_rc
}

# 一个协议族可以用的 iptables 命令，按顺序试。
# NAT 小鸡上常见：默认的 iptables 是 nft 版，内核或容器不支持，旧版 iptables-legacy 却能用。
ipt_candidates() {
  if [ "$1" = 6 ]; then
    printf '%s\n' ip6tables ip6tables-legacy ip6tables-nft
  else
    printf '%s\n' iptables iptables-legacy iptables-nft
  fi
}

# 探测一个协议族的 iptables 能力，结果放在 P_ 开头的变量里。P_BIN 是能用的命令。
# IPv4 和 IPv6 分开探：有的机器 ip6tables 缺模块，不能拿 IPv4 的结果套用。
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
    # 记下报错，都用不了时给用户看。
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

# 有没有改防火墙的权限（CAP_NET_ADMIN）。商家没给这个权限的容器，root 也改不了。
# 看不出来时当作有，交给后面实际试。
has_net_admin() {
  _hn_cap=$(awk '/^CapEff:/ { print $2; exit }' /proc/self/status 2>/dev/null)
  [ -n "$_hn_cap" ] || return 0
  # CAP_NET_ADMIN 是第 12 位，在倒数第 4 个十六进制数字里。
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
  for _fam in 4 6; do
    for _v in OK SET STRING MULTI REJECT RESET ICASE; do
      eval "V${_fam}_$_v=0"
    done
    eval "V${_fam}_BIN='' V${_fam}_ALGO=bm"
  done
  has_net_admin || return 0
  for _m in ip_tables iptable_filter ip6_tables ip6table_filter ip_set ip_set_hash_net \
    xt_set xt_string xt_multiport nf_tables; do
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
  elif command -v nft >/dev/null 2>&1; then
    if nft add table inet vpsfengjin_t >/dev/null 2>"$WORKDIR/nft.err" \
      && nft delete table inet vpsfengjin_t >/dev/null 2>&1; then
      FW_BACKEND=nft
    else
      printf 'nft：%s\n' "$(head -n 1 "$WORKDIR/nft.err")" >>"$WORKDIR/fw.err"
    fi
  fi
}

# 防火墙用不了时，用大白话说清楚原因和影响。
fw_explain() {
  say_warn "这台机器改不了防火墙，改为“只拦域名”。"
  if ! has_net_admin; then
    say "  原因：这台机器是容器，商家没有给它改防火墙的权限（NET_ADMIN），root 也改不了。"
  else
    say "  原因：防火墙命令都报错："
    sed 's/^/    /' "$WORKDIR/fw.err"
  fi
  say "  只拦域名的效果：这台机器（包括你搭的节点）查不到名单里的域名，也就打不开这些网站和 App。"
  say "  做不到的：名单里的 IP / 网段封不了；节点程序如果自己指定了别的 DNS，可能拦不住。"
  say "  想全部封住，可以请商家开通 iptables（NET_ADMIN）权限，开好后再运行一次脚本。"
}

# 设置前先看这台机器能不能改防火墙。缺 iptables / ipset 先试着装，
# 实在不行再用 nftables；都不行就只拦域名（FW_BACKEND=none）。
fw_precheck() {
  [ "${FW_CHECKED:-0}" = 1 ] && return 0
  FW_CHECKED=1
  PROBED=0
  if has_net_admin; then
    command -v iptables >/dev/null 2>&1 || need_cmd iptables iptables || true
    command -v ipset >/dev/null 2>&1 || need_cmd ipset ipset || true
    probe_firewall
    # Alpine 3.19 起 iptables 默认是 nft 版，旧版接口要单独装。
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
  case $FW_BACKEND in
    none) fw_explain ;;
    nft) say_ok "防火墙：nftables" ;;
    *)
      if [ "$V4_SET" = 1 ]; then
        say_ok "防火墙：$V4_BIN + ipset"
      else
        say_warn "有 $V4_BIN，但 ipset 用不了（常见于部分 NAT 小鸡）。地址只能一条条写进规则，最多写 $(no_ipset_rule_cap) 条，超出的不拦。"
      fi
      ;;
  esac
}

ipv6_on() {
  [ -r /proc/net/if_inet6 ] || return 1
  [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = 1 ] && return 1
  return 0
}

#----------------------------------------------------------------------
# 写防火墙。都是整体替换：新规则准备好再一次换上，换的过程中旧规则一直有效；
# 新规则加不上时，旧规则原样留着，不会出现一条都不拦的空档。
#----------------------------------------------------------------------

# legacy 和 nft 两套规则表是分开的，每种命令都清一遍。
remove_ipt_family() {
  for _rf_bin in $(ipt_candidates "$1"); do
    command -v "$_rf_bin" >/dev/null 2>&1 || continue
    while "$_rf_bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
      "$_rf_bin" -D OUTPUT -j "$CHAIN" >/dev/null 2>&1 || break
    done
    "$_rf_bin" -F "$CHAIN" >/dev/null 2>&1
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

# load_set 4|6：地址装进临时集合，再和正式集合对调。
load_set() {
  if [ "$1" = 6 ]; then _ls_name=$SET6; else _ls_name=$SET4; fi
  ipset destroy "${_ls_name}_n" >/dev/null 2>&1
  fengjin_awk ipset plan="$CFG" fam="$1" setname="$_ls_name" >"$WORKDIR/set$1" || return 0
  if ! ipset restore <"$WORKDIR/set$1"; then
    ipset destroy "${_ls_name}_n" >/dev/null 2>&1
    say_err "IPv$1 地址集没有写进去。"
    return 1
  fi
  if ! ipset swap "${_ls_name}_n" "$_ls_name" >/dev/null 2>&1; then
    ipset rename "${_ls_name}_n" "$_ls_name" >/dev/null 2>&1 || {
      ipset destroy "${_ls_name}_n" >/dev/null 2>&1
      say_err "IPv$1 地址集换不上去。"
      return 1
    }
  fi
  ipset destroy "${_ls_name}_n" >/dev/null 2>&1
  return 0
}

# apply_ipt_family 4|6 [1=先不拦 DNS 查询]
apply_ipt_family() {
  _af=$1
  _af_nodns=${2:-0}
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
    rtcp="$_af_rtcp" roth="$_af_roth" useset="$_af_set" cap="$(no_ipset_rule_cap)" nodns="$_af_nodns" \
    chain="$CHAIN" set4="$SET4" set6="$SET6" >"$_af_rules"
  if [ ! -s "$_af_rules" ]; then
    remove_ipt_family "$_af"
    return 0
  fi
  if command -v "$_af_bin-restore" >/dev/null 2>&1; then
    # --noflush 只清空并重写这一条链，别的防火墙规则不动；整个文件一次生效。
    {
      printf '*filter\n:%s - [0:0]\n' "$CHAIN"
      cat "$_af_rules"
      printf 'COMMIT\n'
    } >"$_af_rules.restore"
    if ! "$_af_bin-restore" --noflush <"$_af_rules.restore"; then
      say_err "IPv$_af 规则没有加上，原来的规则保持不变。"
      return 1
    fi
  else
    # 没有 iptables-restore 的极简系统：只能一条条加。
    "$_af_bin" -N "$CHAIN" >/dev/null 2>&1
    "$_af_bin" -F "$CHAIN" >/dev/null 2>&1
    set -f
    while IFS= read -r _af_rule; do
      # 规则里没有空格以外的特殊字符，按空格拆开正好是 iptables 的参数。
      # shellcheck disable=SC2086
      if ! "$_af_bin" $_af_rule; then
        set +f
        "$_af_bin" -F "$CHAIN" >/dev/null 2>&1
        say_err "规则没有加上：$_af_rule"
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

# apply_firewall [1=先不拦 DNS 查询]
apply_firewall() {
  _fw_nodns=${1:-0}
  probe_firewall
  _fw_do6=0
  ipv6_on && _fw_do6=1
  case $FW_BACKEND in
    iptables)
      remove_nft
      if [ "$V4_SET" = 1 ]; then
        load_set 4 || return 1
      elif [ "$(count_lines "$CFG/v4")" -gt "$(no_ipset_rule_cap)" ]; then
        say_warn "没有 ipset，IPv4 只封前 $(no_ipset_rule_cap) 条地址，后面的不拦。"
      fi
      if [ "$_fw_do6" = 1 ] && [ "$V6_SET" = 1 ]; then
        load_set 6 || return 1
      fi
      apply_ipt_family 4 "$_fw_nodns" || return 1
      if [ "$_fw_do6" = 1 ]; then
        apply_ipt_family 6 "$_fw_nodns" || return 1
      else
        remove_ipt_family 6
      fi
      # 名单里已经没有的那一类地址，集合也不用留着。还被规则引用时删不掉，不要紧。
      [ -s "$CFG/v4" ] && [ "$V4_SET" = 1 ] || remove_sets "$SET4"
      [ -s "$CFG/v6" ] && [ "$V6_SET" = 1 ] && [ "$_fw_do6" = 1 ] || remove_sets "$SET6"
      ;;
    nft)
      remove_ipt_family 4
      remove_ipt_family 6
      remove_sets "$SET4" "$SET6"
      # 先建空表再删，再整张表重建，三步在同一个事务里，一起生效。
      {
        printf 'table inet %s\n' "$NFT_TABLE"
        printf 'delete table inet %s\n' "$NFT_TABLE"
        fengjin_awk nft plan="$CFG" table="$NFT_TABLE"
      } >"$WORKDIR/rules.nft"
      if ! nft -f "$WORKDIR/rules.nft"; then
        say_err "nft 规则没有加上，原来的规则保持不变。"
        return 1
      fi
      ;;
    *)
      say_err "现在用不了防火墙，规则没生效。"
      return 1
      ;;
  esac
  return 0
}

# 规则还在不在。被别的防火墙（firewalld、ufw 重载）清掉时，status 会提示。
rules_live() {
  case $(cat "$CFG/backend" 2>/dev/null) in
    none)
      # 只拦域名：看 dnsmasq 还在不在、hosts 里的记录还在不在。
      case $(cat "$CFG/dns.method" 2>/dev/null) in
        dnsmasq) dnsmasq_up ;;
        *) grep -q '^# BEGIN vps-fengjin$' /etc/hosts 2>/dev/null ;;
      esac
      ;;
    nft) nft list table inet "$NFT_TABLE" >/dev/null 2>&1 ;;
    *)
      for _rl_bin in $(ipt_candidates 4) $(ipt_candidates 6); do
        "$_rl_bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1 && return 0
      done
      return 1
      ;;
  esac
}

#----------------------------------------------------------------------
# 域名：整机封禁才拦解析。按端口封时只封解析到的 IP。
#----------------------------------------------------------------------

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
    say_warn "/etc/hosts 只写入前 2000 个域名，太多会拖慢这台机器。"
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
    head -n 2000 "$CFG/dns.list" | awk 'NF { print "0.0.0.0 " $1; print ":: " $1 }'
    printf '%s\n' "# END vps-fengjin"
  } >"$WORKDIR/hosts.new"
  # 内容没变就不写，定时刷新时不反复改文件。
  cmp -s "$WORKDIR/hosts.new" /etc/hosts 2>/dev/null && return 0
  if ! cat "$WORKDIR/hosts.new" 2>/dev/null >/etc/hosts; then
    say_err "/etc/hosts 改不了（只读），域名拦不住。"
    return 1
  fi
}

# 两种情况：
#   本来就在跑的 dnsmasq（OpenWrt 路由、别的程序装的）：只追加拦截的域名，
#     不碰它的监听地址和上游，否则会把局域网的 DNS 弄坏。
#   脚本自己装、自己拉起来的：记在 dnsmasq.owned，只听 127.0.0.1。
#     关闭时连服务一起停掉，免得重启后按默认配置对外开放 53 端口。
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
  if grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null && [ -f "$CFG/resolv.conf.bak" ]; then
    cat "$CFG/resolv.conf.bak" >/etc/resolv.conf
  fi
  if [ -f "$CFG/dnsmasq.owned" ]; then
    stop_dnsmasq
    rm -f "$CFG/dnsmasq.owned"
  elif [ "$_dc_changed" = 1 ] && pidof dnsmasq >/dev/null 2>&1; then
    restart_dnsmasq || true
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
    # 不写地址的 address=/域名/ 对 IPv4、IPv6 都回“不存在”，子域名一起拦。
    awk 'NF { print "address=/" $1 "/" }' "$CFG/dns.list"
  } >"$1"
}

# dnsmasq.conf 里有没有真正生效的 conf-dir。Debian 系的启动脚本自己会带上 /etc/dnsmasq.d。
dnsmasq_reads_confdir() {
  grep -q '^CONFIG_DIR=/etc/dnsmasq.d' /etc/default/dnsmasq 2>/dev/null && return 0
  grep -E -q '^[[:space:]]*conf-dir=/etc/dnsmasq\.d' /etc/dnsmasq.conf 2>/dev/null
}

dnsmasq_up() {
  pidof dnsmasq >/dev/null 2>&1
}

kill_dnsmasq() {
  _kd_pids=$(pidof dnsmasq 2>/dev/null)
  [ -n "$_kd_pids" ] || return 0
  # shellcheck disable=SC2086
  kill $_kd_pids >/dev/null 2>&1
  sleep 1
}

# 每种启动方式试过都看一眼 dnsmasq 真的在跑没有。
# 容器里没有 systemd，也没有在跑的 openrc，服务命令可能“成功”却什么都没启动，
# 最后直接运行 dnsmasq（它自己会转到后台）。
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
  dnsmasq >/dev/null 2>&1
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

dnsmasq_apply() {
  [ -s "$CFG/dns.list" ] || return 0
  _dm_shared=0
  if [ ! -f "$CFG/dnsmasq.owned" ] && { [ "$OS_ID" = openwrt ] || pidof dnsmasq >/dev/null 2>&1; }; then
    _dm_shared=1
  fi
  if [ "$_dm_shared" = 0 ]; then
    # resolv.conf 是链接时归 systemd-resolved 之类管，本机不会来问这个 dnsmasq，拦了等于没拦。
    [ -L /etc/resolv.conf ] && return 1
    pick_resolver
    case $RESOLVER in dig|host|nslookup) ;; *) return 1 ;; esac
  fi
  mkdir -p /etc/dnsmasq.d 2>/dev/null
  [ -d /etc/dnsmasq.d ] || return 1
  # 先写好配置再装，Debian 装完会马上启动，这样一开始就只听 127.0.0.1。
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
    printf '\n%s\n' "conf-dir=/etc/dnsmasq.d/,*.conf" >>/etc/dnsmasq.conf
    printf '%s\n' 1 >"$CFG/dnsmasq.confdir"
    _dm_changed=1
  fi
  if [ "$_dm_shared" = 1 ]; then
    if [ "$_dm_changed" = 1 ] || ! pidof dnsmasq >/dev/null 2>&1; then
      restart_dnsmasq || { dnsmasq_clear; return 1; }
    fi
    return 0
  fi
  if [ ! -f "$CFG/resolv.conf.bak" ] && [ -f /etc/resolv.conf ] \
    && ! grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null; then
    cp /etc/resolv.conf "$CFG/resolv.conf.bak" || return 1
  fi
  printf '%s\n' 1 >"$CFG/dnsmasq.owned"
  if [ "$_dm_changed" = 1 ] || ! pidof dnsmasq >/dev/null 2>&1; then
    restart_dnsmasq || { dnsmasq_clear; return 1; }
  fi
  # 确认 dnsmasq 真的能回答，才把本机 DNS 指过去，不然这台机器会断网。
  if [ -z "$(resolve_probe iana.org 127.0.0.1)" ]; then
    dnsmasq_clear
    return 1
  fi
  # 有的容器平台把 resolv.conf 设成只读，写不进去就别假装成功。
  if ! printf '%s\n' "# vps-fengjin managed" "nameserver 127.0.0.1" >/etc/resolv.conf 2>/dev/null; then
    say_warn "/etc/resolv.conf 改不了（只读），本机不会去问 dnsmasq。"
    dnsmasq_clear
    return 1
  fi
  return 0
}

# 按方式写好域名拦截，并清掉其他方式留下的东西。
dns_apply() {
  case $1 in
    hosts)
      dnsmasq_clear
      hosts_apply
      ;;
    dnsmasq)
      hosts_clear
      if ! dnsmasq_apply; then
        say_warn "dnsmasq 没接好，改写入 /etc/hosts（子域名拦不住）。"
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

# load_rules [1=同时写域名拦截]
load_rules() {
  probe_firewall
  _lr_method=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  if [ "$_lr_method" = string ] && { [ "$FW_BACKEND" != iptables ] || [ "$V4_STRING" != 1 ]; }; then
    say_warn "当前防火墙不能按域名拦 DNS 查询，改写入 /etc/hosts。"
    _lr_method=hosts
    printf '%s\n' hosts >"$CFG/dns.method"
  fi
  if [ "$FW_BACKEND" = none ]; then
    # 只拦域名：没有防火墙规则可写。开机时也要把 dnsmasq 拉起来（容器里不会自己起）。
    dns_apply "$_lr_method" || return 1
    return 0
  fi
  apply_firewall 0 || return 1
  [ "${1:-0}" = 1 ] && dns_apply "$_lr_method"
  return 0
}

disable_all() {
  remove_firewall
  hosts_clear
  dnsmasq_clear
}

#----------------------------------------------------------------------
# 域名解析成 IP
#----------------------------------------------------------------------

pick_resolver() {
  RESOLVER=none
  for _r in dig host nslookup getent; do
    if command -v "$_r" >/dev/null 2>&1; then
      RESOLVER=$_r
      return 0
    fi
  done
}

# 设置时可以装一个查 DNS 的命令；定时刷新不装软件。
ensure_resolver() {
  pick_resolver
  case $RESOLVER in dig|host|nslookup) return 0 ;; esac
  [ "${1:-}" = setup ] || return 0
  say_info "没有查 DNS 的命令，尝试装一个。"
  need_cmd dig dnsutils bind9-dnsutils bind-utils bind-tools bind-dig bind || true
  pick_resolver
}

with_timeout() {
  _wt_secs=$1
  shift
  # 老版本 busybox 的 timeout 要写成 timeout -t 秒数，先试一次看哪种能用。
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

# 查一个名字，打印查到的 IP（可能为空）。$2 是 DNS 服务器。
resolve_probe() {
  pick_resolver
  case $RESOLVER in
    dig) dig "@$2" +time=2 +tries=1 +short "$1" A 2>/dev/null ;;
    host) host -W 2 -t A "$1" "$2" 2>/dev/null ;;
    nslookup) with_timeout 5 nslookup "$1" "$2" 2>/dev/null ;;
    *) : ;;
  esac | fengjin_awk extract server="$2"
}

# 挑一个能用的上游 DNS。本机配置的优先，不通再试公共的。
# 只有 getent 时没法指定服务器，用系统默认的。
pick_dns_server() {
  DNS_SERVER=""
  case $RESOLVER in dig|host|nslookup) ;; *) return 0 ;; esac
  for _ps in $(cat "$CFG/upstream.dns" 2>/dev/null) 1.1.1.1 8.8.8.8 223.5.5.5; do
    if [ -n "$(resolve_probe example.com "$_ps")" ]; then
      DNS_SERVER=$_ps
      return 0
    fi
  done
  DNS_SERVER=$(awk 'NF { print; exit }' "$CFG/upstream.dns" 2>/dev/null)
  [ -n "$DNS_SERVER" ] || DNS_SERVER=1.1.1.1
}

# 一个解析进程：按顺序查完自己那份名字。$1 名字 $2 服务器 $3 结果 $4 进度
resolve_worker() {
  _rw_done=0
  : >"$3"
  case $RESOLVER in
    dig)
      # 每 50 个名字交给 dig 一次（批量文件），少起很多进程。
      # +question 会把问的是哪个名字也印出来，用来数解析成功了几个。
      awk -v s="$2" -v base="$3.q" '
        {
          f = base "." int((NR - 1) / 50)
          if (f != last) { if (last != "") close(last); last = f }
          print "@" s " " $1 " A +time=2 +tries=1 +noall +question +answer" > f
          print "@" s " " $1 " AAAA +time=2 +tries=1 +noall +question +answer" > f
        }
      ' "$1"
      for _rw_q in "$3".q.*; do
        [ -f "$_rw_q" ] || continue
        dig -f "$_rw_q" >>"$3" 2>/dev/null
        _rw_done=$((_rw_done + $(count_lines "$_rw_q") / 2))
        printf '%s\n' "$_rw_done" >"$4"
        rm -f "$_rw_q"
      done
      ;;
    *)
      while IFS= read -r _rw_name; do
        [ -n "$_rw_name" ] || continue
        printf '@@@ %s\n' "$_rw_name" >>"$3"
        case $RESOLVER in
          host) host -W 2 "$_rw_name" "$2" >>"$3" 2>/dev/null ;;
          nslookup) with_timeout 5 nslookup "$_rw_name" "$2" >>"$3" 2>/dev/null ;;
          getent) with_timeout 4 getent hosts "$_rw_name" >>"$3" 2>/dev/null ;;
        esac
        _rw_done=$((_rw_done + 1))
        printf '%s\n' "$_rw_done" >"$4"
      done <"$1"
      ;;
  esac
}

# resolve_names 名字文件 结果文件。设 RES_TOTAL、RES_OK。
resolve_names() {
  RES_TOTAL=$(count_lines "$1")
  RES_OK=0
  : >"$2"
  [ "$RES_TOTAL" -gt 0 ] || return 0
  _rn_dir=$WORKDIR/resolve
  rm -rf "$_rn_dir"
  mkdir -p "$_rn_dir"
  _rn_w=$(resolve_workers)
  [ "$_rn_w" -le "$RES_TOTAL" ] || _rn_w=$RES_TOTAL
  # 名字轮流分给每个进程，各查各的，互不等待。
  awk -v n="$_rn_w" -v d="$_rn_dir" 'NF { print > (d "/chunk." (NR % n)) }' "$1"
  _rn_pids=""
  for _rn_c in "$_rn_dir"/chunk.*; do
    _rn_id=${_rn_c##*.}
    resolve_worker "$_rn_c" "$DNS_SERVER" "$_rn_dir/out.$_rn_id" "$_rn_dir/prog.$_rn_id" &
    _rn_pids="$_rn_pids $!"
  done
  while :; do
    _rn_alive=0
    for _rn_p in $_rn_pids; do
      kill -0 "$_rn_p" 2>/dev/null && _rn_alive=1
    done
    if [ -t 1 ]; then
      _rn_n=$(cat "$_rn_dir"/prog.* 2>/dev/null | awk '{ s += $1 } END { print s + 0 }')
      printf '\r  已解析 %s / %s' "$_rn_n" "$RES_TOTAL"
    fi
    [ "$_rn_alive" = 1 ] || break
    sleep 1
  done
  wait
  [ -t 1 ] && printf '\r  已解析 %s / %s\n' "$RES_TOTAL" "$RES_TOTAL"
  cat "$_rn_dir"/out.* 2>/dev/null \
    | fengjin_awk extract server="$DNS_SERVER" okfile="$_rn_dir/ok" >"$2"
  RES_OK=$(cat "$_rn_dir/ok" 2>/dev/null || echo 0)
  [ "$RES_OK" -le "$RES_TOTAL" ] || RES_OK=$RES_TOTAL
  rm -rf "$_rn_dir"
}

save_upstreams() {
  if grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null && [ -s "$CFG/upstream.dns" ]; then
    return 0
  fi
  : >"$CFG/upstream.dns"
  # systemd-resolved 的 resolv.conf 只写 127.0.0.53，真正的上游在 /run 里那份。
  # Docker 的 127.0.0.11 是真正的上游，要留着。
  for _sf in /etc/resolv.conf /run/systemd/resolve/resolv.conf; do
    [ -s "$CFG/upstream.dns" ] && break
    awk '$1 == "nameserver" && $2 != "127.0.0.1" && $2 != "127.0.0.53" && $2 != "::1" { print $2 }' "$_sf" \
      >"$CFG/upstream.dns" 2>/dev/null
  done
  [ -s "$CFG/upstream.dns" ] || printf '%s\n' 1.1.1.1 8.8.8.8 >"$CFG/upstream.dns"
}

choose_dns_method() {
  if [ "$1" -eq 0 ]; then
    printf '%s\n' none
  elif [ "$FW_BACKEND" = none ]; then
    # 只拦域名：要连子域名一起拦，优先 dnsmasq，装不上才用 hosts。
    if [ "$OS_ID" = openwrt ] || command -v dnsmasq >/dev/null 2>&1 || [ "${PM:-none}" != none ]; then
      printf '%s\n' dnsmasq
    else
      printf '%s\n' hosts
    fi
  elif [ "$2" != all ]; then
    printf '%s\n' none
  elif [ "$OS_ID" = openwrt ]; then
    printf '%s\n' dnsmasq
  elif [ "$1" -le 400 ] && [ "$FW_BACKEND" = iptables ] && [ "$V4_STRING" = 1 ]; then
    printf '%s\n' string
  elif [ "$1" -le 400 ]; then
    printf '%s\n' hosts
  elif command -v dnsmasq >/dev/null 2>&1 || [ "${PM:-none}" != none ]; then
    printf '%s\n' dnsmasq
  else
    printf '%s\n' hosts
  fi
}

#----------------------------------------------------------------------
# 不能封的地址：你的 SSH 来源、本机地址、本机用的 DNS 服务器。
# 封了它们会把自己锁在外面，或者让这台机器整个解析不了域名。
#----------------------------------------------------------------------

# /proc/net/tcp(6) 里正在连着 sshd 端口的远端地址。
ssh_peers_from_proc() {
  _sp_ports=22
  set -- ${SSH_CONNECTION:-}
  [ -n "${4:-}" ] && _sp_ports="$_sp_ports $4"
  _sp_ports="$_sp_ports $(awk 'tolower($1) == "port" { print $2 }' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
  _sp_hex=$(for _p in $_sp_ports; do printf '%04X ' "$_p" 2>/dev/null; done)
  for _sp_f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$_sp_f" ] || continue
    awk -v ports=" $_sp_hex" '
      function h2d(h,   i, v) {
        v = 0
        h = toupper(h)
        for (i = 1; i <= length(h); i++) v = v * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1
        return v
      }
      # 内核按机器字节序存，每 4 字节一组要倒过来（按常见的小端机器处理）。
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
        if (substr(full, 1, 24) == "00000000000000000000FFFF") { print dotted(substr(full, 25, 8)); next }
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
  for _ce_v in "${SSH_CONNECTION:-}" "${SSH_CLIENT:-}"; do
    set -- $_ce_v
    [ -n "${1:-}" ] && printf '%s\n' "$1" >>"$WORKDIR/ssh.now"
  done
  # 定时刷新没有 SSH 环境变量。把设置时的登录地址记下来，以后每次都躲开。
  if [ -s "$WORKDIR/ssh.now" ]; then
    cat "$WORKDIR/ssh.now" "$CFG/ssh.peers" 2>/dev/null | LC_ALL=C sort -u | tail -n 20 >"$WORKDIR/ssh.peers"
    cat "$WORKDIR/ssh.peers" >"$CFG/ssh.peers"
  fi
  cat "$CFG/ssh.peers" >>"$_ce_out" 2>/dev/null
  ssh_peers_from_proc >>"$_ce_out"
  if command -v ip >/dev/null 2>&1; then
    ip -o addr show 2>/dev/null | awk '$3 == "inet" || $3 == "inet6" { split($4, a, "/"); print a[1] }' >>"$_ce_out"
  fi
  cat "$CFG/upstream.dns" >>"$_ce_out" 2>/dev/null
  [ -n "${DNS_SERVER:-}" ] && printf '%s\n' "$DNS_SERVER" >>"$_ce_out"
  LC_ALL=C sort -u "$_ce_out" -o "$_ce_out"
}

# filter_family 4|6 原始地址 输出 排除表
filter_family() {
  : >"$WORKDIR/skip.$1"
  : >"$3"
  [ -s "$2" ] || return 0
  LC_ALL=C sort -u "$2" | awk -v fam="$1" '
    NF { print (index($0, "/") > 0 ? "net" : "ip") fam "\t" $0 }
  ' | fengjin_awk overlap peers="$4" skipfile="$WORKDIR/skip.$1" \
    | awk -F '\t' 'NF >= 2 { print $2 }' >"$3"
}

# 把名单变成要封的 IP 表和要拦的域名表。$1 = setup 或 refresh
rebuild_ips() {
  _rb_mode=$(cat "$CFG/mode")
  for _f in v4.raw v6.raw dns.names www.names resolved; do
    : >"$WORKDIR/$_f"
  done
  awk -F '\t' -v w="$WORKDIR" '
    $1 == "ip4" || $1 == "net4" { print $2 > (w "/v4.raw"); next }
    $1 == "ip6" || $1 == "net6" { print $2 > (w "/v6.raw"); next }
    $1 == "domain" || $1 == "suffix" {
      # 后缀顺带记下 www.，下面按拦截方式决定要不要一起解析。
      print $2 > (w "/dns.names")
      if ($1 == "suffix" && $2 !~ /^www\./) print "www." $2 > (w "/www.names")
    }
  ' "$CFG/list.txt"
  LC_ALL=C sort -u "$WORKDIR/dns.names" -o "$WORKDIR/dns.list"
  _rb_nnames=$(count_lines "$WORKDIR/dns.list")
  _rb_method=$(choose_dns_method "$_rb_nnames" "$_rb_mode")
  if [ "$FW_BACKEND" = none ]; then
    # 只拦域名：IP 没处封，也就不用解析域名。
    : >"$CFG/v4"
    : >"$CFG/v6"
    cat "$WORKDIR/dns.list" >"$CFG/dns.list"
    printf '%s\n' "$_rb_method" >"$CFG/dns.method"
    return 0
  fi
  # 后缀只能解析主名字。按端口封、或者域名拦截只靠 hosts 时，顺带解析 www.，
  # dnsmasq 和拦 DNS 查询本身就连子域名一起拦，不用多查一倍。
  # 后缀超过 5000 个（例如整份去广告名单）也不加，不然小鸡要多跑一倍的时间。
  _rb_www=$(count_lines "$WORKDIR/www.names")
  case $_rb_method in
    string|dnsmasq) _rb_www=0 ;;
    *) [ "$_rb_www" -le 5000 ] || _rb_www=0 ;;
  esac
  if [ "$_rb_www" -gt 0 ]; then
    cat "$WORKDIR/dns.names" "$WORKDIR/www.names" | LC_ALL=C sort -u >"$WORKDIR/names"
  else
    LC_ALL=C sort -u "$WORKDIR/dns.names" -o "$WORKDIR/names"
  fi
  if [ "$_rb_nnames" -gt 0 ]; then
    ensure_resolver "$1"
    if [ "$RESOLVER" = none ]; then
      say_warn "没有查 DNS 的命令，域名这次变不成 IP。"
    else
      # 刷新时拦 DNS 查询的规则也会挡住脚本自己的查询，先换成不拦查询的规则。
      if [ "$FW_BACKEND" = iptables ] && "$V4_BIN" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
        apply_firewall 1 >/dev/null 2>&1 || true
      fi
      pick_dns_server
      say_step "把域名解析成 IP（$(count_lines "$WORKDIR/names") 个，$(resolve_workers) 路同时查，DNS：${DNS_SERVER:-系统默认}）"
      resolve_names "$WORKDIR/names" "$WORKDIR/resolved"
      if [ "$RES_OK" -lt "$RES_TOTAL" ]; then
        say_info "解析到 $RES_OK 个，$((RES_TOTAL - RES_OK)) 个没有结果（不存在或超时）。"
      fi
    fi
  fi
  # 一个都没解析出来，多半是网络临时断了。沿用上次的结果，别让定时刷新把域名的 IP 全放开。
  if [ -s "$WORKDIR/resolved" ]; then
    cp "$WORKDIR/resolved" "$CFG/resolved.last"
  elif [ "$_rb_nnames" -gt 0 ] && [ -s "$CFG/resolved.last" ]; then
    say_warn "这次一个域名都没解析到，沿用上次解析到的 IP。"
    cp "$CFG/resolved.last" "$WORKDIR/resolved"
  fi
  awk -v w="$WORKDIR" 'NF { print >> (w (index($0, ":") ? "/v6.raw" : "/v4.raw")) }' "$WORKDIR/resolved"
  collect_excludes "$WORKDIR/exclude"
  filter_family 4 "$WORKDIR/v4.raw" "$CFG/v4" "$WORKDIR/exclude"
  filter_family 6 "$WORKDIR/v6.raw" "$CFG/v6" "$WORKDIR/exclude"
  cat "$WORKDIR/dns.list" >"$CFG/dns.list"
  printf '%s\n' "$_rb_method" >"$CFG/dns.method"
  cat "$WORKDIR/skip.4" "$WORKDIR/skip.6" >"$WORKDIR/skipped" 2>/dev/null
  if [ -s "$WORKDIR/skipped" ]; then
    say_warn "下面这些地址包含你的 SSH 来源、本机地址或本机用的 DNS 服务器，已跳过："
    head -n 8 "$WORKDIR/skipped" | awk -F '\t' '{ print "  " $1 "（包含 " $2 "）" }'
  fi
  if [ "$_rb_mode" != all ] && [ "$_rb_nnames" -gt 0 ]; then
    say_info "按端口封时，只封这些域名现在解析到的 IP。新冒出来的子域名要等下次刷新（每 6 小时一次）。"
  fi
}

#----------------------------------------------------------------------
# 开机继续生效、定时刷新
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

# 把正在跑的脚本装成 vps-fengjin 命令。开机自启和定时刷新都调它。
install_self() {
  _is_dest=$BIN_DEFAULT
  mkdir -p /usr/local/sbin 2>/dev/null || _is_dest=/usr/sbin/vps-fengjin
  _is_src=$0
  case $_is_src in
    /*) ;;
    *) _is_src=$(pwd)/$_is_src ;;
  esac
  if [ ! -f "$_is_src" ] || ! grep -q 'vps-fengjin-onekey-begin' "$_is_src" 2>/dev/null; then
    # 例如 curl ... | sh：脚本没有落成文件，没法装成命令。
    [ -x "$(installed_bin)" ] && return 0
    die "请先把脚本下载成文件再运行（README 里的一键命令就是这样做的），不然装不成 vps-fengjin 命令，重启后也不会自动封上。"
  fi
  [ "$_is_src" = "$_is_dest" ] && return 0
  cp "$_is_src" "$_is_dest.new" && chmod 755 "$_is_dest.new" && mv -f "$_is_dest.new" "$_is_dest"
}

write_systemd() {
  mkdir -p /etc/systemd/system
  # 排在常见防火墙服务之后：它们启动时会清空规则，排在后面才不会被冲掉。
  cat >/etc/systemd/system/vps-fengjin.service <<EOF
[Unit]
Description=Apply saved outbound block list
After=network.target firewalld.service ufw.service netfilter-persistent.service nftables.service iptables.service docker.service

[Service]
Type=oneshot
ExecStart=$1 apply-rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/vps-fengjin-refresh.service <<EOF
[Unit]
Description=Refresh outbound block list addresses

[Service]
Type=oneshot
ExecStart=$1 refresh
EOF
  cat >/etc/systemd/system/vps-fengjin-refresh.timer <<EOF
[Unit]
Description=Refresh outbound block list every 6 hours

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
  # rc.local 最后一行常是 exit 0，加在它后面不会执行，所以插到它前面。
  awk -v line="$2" '
    { lines[++n] = $0 }
    END {
      at = n + 1
      for (i = n; i >= 1; i--) { if (lines[i] ~ /^[ \t]*exit[ \t]+0[ \t]*$/) { at = i; break } if (lines[i] !~ /^[ \t]*$/) break }
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
  _ip_names=$(count_lines "$CFG/dns.list")
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    write_systemd "$_ip_bin"
    if [ "$_ip_names" -gt 0 ]; then
      systemctl enable --now vps-fengjin-refresh.timer >/dev/null 2>&1
    else
      systemctl disable --now vps-fengjin-refresh.timer >/dev/null 2>&1
    fi
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
    # OpenWrt 重载防火墙时会清掉规则，firewall.user 会在每次重载后执行。
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
  else
    say_warn "这台机器没有开机自启的地方（容器里常见）。机器或容器重启后，运行一次 vps-fengjin on 就会重新生效。"
  fi
  remove_cron
  [ "$_ip_names" -gt 0 ] || return 0
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
  # OpenWrt 要先 disable，不然 /etc/rc.d 里留下指向空文件的链接。
  if [ -f /etc/openwrt_release ] && [ -x /etc/init.d/vps-fengjin ]; then
    /etc/init.d/vps-fengjin disable >/dev/null 2>&1
  fi
  rm -f /etc/init.d/vps-fengjin
  remove_cron
  strip_marked_file /etc/firewall.user
  strip_marked_file /etc/rc.local
}

#----------------------------------------------------------------------
# 名单：读入、识别、每份单独存。
#   $CFG/sources/<编号>/      已经生效的名单
#   $WORKDIR/sources/<编号>/  这次新加、还没确认的名单
# 每个目录里：name 备注名，kind 来源（url / file / paste / old），
#   origin 网址或文件路径，count「域名 后缀 IP」个数，list 识别后的名单。
#----------------------------------------------------------------------

fetch_url() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 120 --max-filesize "$LIST_MAX_BYTES" -o "$2" "$1" && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 60 -O "$2" "$1" && return 0
  fi
  return 1
}

# read_source 网址/路径/- 输出：把名单原文放进输出文件。
read_source() {
  list_limits
  : >"$2"
  case $1 in
    http://*|https://*)
      if ! fetch_url "$1" "$2"; then
        say_err "下载失败。请检查网址拼写，以及这台机器能不能连上那个网站。"
        return 1
      fi
      ;;
    *://*)
      say_err "只接受 http 或 https 网址。"
      return 1
      ;;
    -)
      save_stdin
      cat <&4 >"$2"
      ;;
    *)
      if [ ! -f "$1" ]; then
        say_err "找不到文件：$1"
        return 1
      fi
      if [ "$(wc -c <"$1")" -gt "$LIST_MAX_BYTES" ]; then
        say_err "文件超过 ${LIST_MAX_MB}MB，这台机器吃不消。"
        return 1
      fi
      cat "$1" >"$2"
      ;;
  esac
  if [ "$(wc -c <"$2")" -gt "$LIST_MAX_BYTES" ]; then
    say_err "名单超过 ${LIST_MAX_MB}MB，这台机器吃不消。"
    return 1
  fi
  case $(dd if="$2" bs=200 count=1 2>/dev/null | tr 'A-Z' 'a-z') in
    *'<html'*|*'<!doctype'*)
      say_err "读到的是网页，不是名单。如果是 GitHub 链接，请用 Raw 按钮打开后的地址。"
      return 1
      ;;
  esac
  return 0
}

bad_reason() {
  case $1 in
    wide) printf '%s\n' "网段太大，怕把整台机器封死" ;;
    local) printf '%s\n' "这是本机或特殊地址" ;;
    keyword) printf '%s\n' "关键词规则太宽，不支持" ;;
    unsupported) printf '%s\n' "这种规则类型不支持" ;;
    *) printf '%s\n' "看不懂" ;;
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

show_bads() {
  [ "$N_BAD" -gt 0 ] || return 0
  say_warn "有 $N_BAD 行没用上，最多显示 8 行："
  awk -F '\t' '$1 == "bad" { print $2 "\t" $3 }' "$1" | head -n 8 | while IFS='	' read -r _sb_code _sb_rest; do
    printf '  %s：%s\n' "$(bad_reason "$_sb_code")" "$_sb_rest"
  done
}

# 识别名单，并按内存截掉超出上限的域名。IP 进 ipset，全部保留。
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
    say_warn "名单里有 $_cr_n 个域名，这台机器最多用 $LIST_MAX_ITEMS 个，后面的不用。"
  fi
  LC_ALL=C sort -u "$WORKDIR/class.keep" >"$2"
}

cap_list() {
  list_limits
  _cl_n=$(awk -F '\t' '$1 == "domain" || $1 == "suffix" { c++ } END { print c + 0 }' "$1")
  [ "$_cl_n" -gt "$LIST_MAX_ITEMS" ] || return 0
  say_warn "几份名单合起来域名超过 $LIST_MAX_ITEMS 个，这台机器只保留前 $LIST_MAX_ITEMS 个。"
  awk -F '\t' -v cap="$LIST_MAX_ITEMS" '
    $1 == "domain" || $1 == "suffix" { if (++c > cap) next }
    { print }
  ' "$1" >"$WORKDIR/list.cap"
  cat "$WORKDIR/list.cap" >"$1"
}

clean_name() {
  printf '%s' "$1" | tr -d '\000-\037' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//'
}

# 列出名单目录。saved：已生效的；pending：这次新加的；all：两者都列。
# 标记了要删除的（$WORKDIR/del.list）不算在 all 里。
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
    url) _ss_from="网址 $_ss_origin" ;;
    file) _ss_from="文件 $_ss_origin" ;;
    paste) _ss_from="粘贴" ;;
    *) _ss_from="升级前的名单" ;;
  esac
  _ss_tag=""
  case $_ss_d in
    "${PENDING:-/nonexistent}"/*) _ss_tag="（本次新加）" ;;
  esac
  grep -qxF "$_ss_d" "$WORKDIR/del.list" 2>/dev/null && _ss_tag="（待删除）"
  printf '  %s) %s%s\n' "$1" "$_ss_name" "$_ss_tag"
  printf '     %s；域名 %s 个，IP / 网段 %s 个\n' "$_ss_from" "$(($2 + $3))" "$4"
}

# 升级前只有一份合并好的 list.txt，把它当成一份名单。
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

# add_source 来源类型 来源 默认备注名 原文文件
add_source() {
  _as_id=$(next_source_id)
  _as_d=$PENDING/$_as_id
  mkdir -p "$_as_d"
  classify_raw "$4" "$_as_d/list"
  summarize_list "$WORKDIR/class.all"
  show_bads "$WORKDIR/class.all"
  summarize_list "$_as_d/list"
  if [ $((N_DOMAIN + N_SUFFIX + N_IP)) -eq 0 ]; then
    say_err "这份名单里没有能用的域名或 IP，没有加进去。"
    rm -rf "$_as_d"
    return 1
  fi
  printf '%s %s %s\n' "$N_DOMAIN" "$N_SUFFIX" "$N_IP" >"$_as_d/count"
  printf '%s\n' "$1" >"$_as_d/kind"
  printf '%s\n' "$2" >"$_as_d/origin"
  printf '%s\n' "$3" >"$_as_d/name"
  say_ok "已添加「$3」：域名 $((N_DOMAIN + N_SUFFIX)) 个，IP / 网段 $N_IP 个"
}

# add_from 网址/路径/-：读入并添加一份名单。
add_from() {
  _af_src=$(printf '%s' "$1" | sed "s/^[\"']//;s/[\"']\$//")
  case $_af_src in
    "~/"*) _af_src=$HOME/${_af_src#"~/"} ;;
  esac
  read_source "$_af_src" "$WORKDIR/raw.txt" || return 1
  case $_af_src in
    http://*|https://*)
      # 默认备注名用网址最后一段，例如 AntiAD.list。
      _af_def=$(printf '%s' "$_af_src" | sed 's/[?#].*//;s|/*$||;s|.*/||')
      add_source url "$_af_src" "${_af_def:-网址名单}" "$WORKDIR/raw.txt"
      ;;
    -) add_source paste "" "标准输入的名单" "$WORKDIR/raw.txt" ;;
    *) add_source file "$_af_src" "$(basename "$_af_src")" "$WORKDIR/raw.txt" ;;
  esac
}

add_paste() {
  input_init
  say "请粘贴名单，一行一个。粘贴完后另起一行输入 END 回车（也可以按 Ctrl+D）。"
  : >"$WORKDIR/raw.txt"
  _ap_n=0
  while IFS= read -r _ap_line <&3; do
    # 从 Windows 终端粘贴时行尾会带 \r 或空格。
    case $_ap_line in
      END|end|END[[:space:]]*|end[[:space:]]*|[[:space:]]*END|[[:space:]]*END[[:space:]]*) break ;;
    esac
    printf '%s\n' "$_ap_line" >>"$WORKDIR/raw.txt"
    _ap_n=$((_ap_n + 1))
    if [ "$_ap_n" -ge 100000 ]; then
      say_warn "已经收了 100000 行，后面的不再收。这么大的名单建议放成文件或网址。"
      break
    fi
  done
  if [ "$_ap_n" -eq 0 ]; then
    say_warn "没有收到内容。"
    return 1
  fi
  say_info "收到 $_ap_n 行。"
  add_source paste "" "粘贴的名单 $(next_source_id)" "$WORKDIR/raw.txt"
}

# manage_sources pending|saved：列出名单，改备注名或删除。
# pending 的直接删；saved 的先标记，回到菜单后确认才真正删。
manage_sources() {
  _ms_scope=$1
  while :; do
    source_dirs "$_ms_scope" >"$WORKDIR/src.idx"
    if [ ! -s "$WORKDIR/src.idx" ]; then
      say_info "还没有名单。"
      return 0
    fi
    say ""
    say "名单："
    _ms_i=0
    while IFS= read -r _ms_d; do
      _ms_i=$((_ms_i + 1))
      show_source_line "$_ms_i" "$_ms_d"
    done <"$WORKDIR/src.idx"
    ask "输入编号修改或删除，直接回车返回：" ""
    [ -n "$ANSWER" ] || return 0
    _ms_d=""
    case $ANSWER in
      *[!0-9]*) ;;
      *) _ms_d=$(sed -n "${ANSWER}p" "$WORKDIR/src.idx") ;;
    esac
    if [ -z "$_ms_d" ]; then
      say_warn "没有这个编号。"
      continue
    fi
    _ms_name=$(cat "$_ms_d/name" 2>/dev/null)
    _ms_marked=0
    grep -qxF "$_ms_d" "$WORKDIR/del.list" 2>/dev/null && _ms_marked=1
    say "「$_ms_name」："
    say "  1) 改备注名"
    if [ "$_ms_marked" = 1 ]; then
      say "  2) 不删了"
    else
      say "  2) 删除"
    fi
    say "  0) 返回"
    ask_pick "请选择 [0]: " 0 1 2 0
    case $ANSWER in
      1)
        ask "新的备注名（现在是「$_ms_name」，回车不改）：" ""
        _ms_new=$(clean_name "$ANSWER")
        if [ -n "$_ms_new" ]; then
          printf '%s\n' "$_ms_new" >"$_ms_d/name"
          say_ok "已改为「$_ms_new」"
          case $_ms_d in
            "$CFG"/*) [ -f "$CFG/mode" ] && write_status ;;
          esac
        fi
        ;;
      2)
        if [ "$_ms_scope" = pending ]; then
          rm -rf "$_ms_d"
          say_ok "已删除「$_ms_name」"
        elif [ "$_ms_marked" = 1 ]; then
          grep -vxF "$_ms_d" "$WORKDIR/del.list" >"$WORKDIR/del.tmp"
          mv "$WORKDIR/del.tmp" "$WORKDIR/del.list"
          say_ok "「$_ms_name」不删了"
        else
          printf '%s\n' "$_ms_d" >>"$WORKDIR/del.list"
          say_ok "「$_ms_name」已标记删除，返回后确认才生效"
        fi
        ;;
    esac
  done
}

# collect_sources new|append：一份份加名单，直到选「下一步」。
# 追加时一份都没加就返回 1。
collect_sources() {
  _cs_mode=$1
  PENDING=$WORKDIR/sources
  rm -rf "$PENDING"
  mkdir -p "$PENDING"
  while :; do
    _cs_n=$(source_dirs pending | awk 'END { print NR }')
    say ""
    say "添加名单（这次已添加 $_cs_n 份）。一行一个，域名和 IP 可以混着写。"
    say "  1) 输入名单网址，或这台机器上的文件路径"
    say "  2) 直接粘贴"
    [ "$_cs_n" -gt 0 ] && say "  3) 查看、改名或删除这次添加的名单"
    if [ "$_cs_n" -gt 0 ]; then
      say "  0) 添加完毕，下一步"
      _cs_def=0
    elif [ "$_cs_mode" = append ]; then
      say "  0) 不追加了，返回"
      _cs_def=1
    else
      say "  按 Ctrl+C 退出"
      _cs_def=1
    fi
    ask "请选择（也可以直接粘贴网址）[$_cs_def]: " "$_cs_def"
    case $ANSWER in
      1)
        ask "名单网址或文件路径（回车返回）：" ""
        [ -n "$ANSWER" ] && add_from "$ANSWER"
        ;;
      2) add_paste ;;
      3)
        if [ "$_cs_n" -gt 0 ]; then
          manage_sources pending
        else
          say_warn "请输入菜单上的数字。"
        fi
        ;;
      0)
        [ "$_cs_n" -gt 0 ] && return 0
        [ "$_cs_mode" = append ] && return 1
        say_warn "还没有名单，请先添加一份。"
        ;;
      http://*|https://*|/*|"~/"*|./*) add_from "$ANSWER" ;;
      *)
        if [ -f "$ANSWER" ]; then
          add_from "$ANSWER"
        else
          say_warn "请输入菜单上的数字，或者名单网址。"
        fi
        ;;
    esac
  done
}

# merge_sources 输出：合并所有要生效的名单（已有的减去标记删除的，加上这次新加的）。
merge_sources() {
  source_dirs all | while IFS= read -r _mg_d; do
    cat "$_mg_d/list"
  done | LC_ALL=C sort -u >"$1"
  cap_list "$1"
}

#----------------------------------------------------------------------
# 封禁范围、确认、生效
#----------------------------------------------------------------------

scope_text() {
  if [ "$1" = all ]; then
    printf '%s\n' "整台机器"
  else
    printf '%s\n' "只封目标端口 $2"
  fi
}

# ask_scope [当前范围 当前端口]：结果放在 MODE、PORTS。
ask_scope() {
  _sc_def=1
  [ "${1:-all}" = ports ] && _sc_def=2
  while :; do
    say ""
    say "封在什么范围？"
    say "  1) 整台机器：不管哪个端口，都连不上名单里的地址（推荐）"
    say "     想让用你节点上网的人打不开名单里的网站和 App，就选这个。"
    say "  2) 只封对方网站的某些端口，例如 443。别的端口还能连"
    say "     注意：这里填的是对方网站的端口，不是你节点的端口。一般用不到。"
    ask_pick "请选择 [$_sc_def]: " "$_sc_def" 1 2
    if [ "$ANSWER" = 1 ]; then
      MODE=all
      PORTS=
      return 0
    fi
    while :; do
      if [ "${1:-}" = ports ] && [ -n "${2:-}" ]; then
        ask "目标端口，用逗号或空格分开（回车沿用 $2，输入 0 返回）：" "$2"
      else
        ask "目标端口，用逗号或空格分开，最多 30 个（输入 0 返回）：" ""
      fi
      [ "$ANSWER" = 0 ] && break
      if [ -z "$ANSWER" ]; then
        say_warn "请输入端口，例如 443。"
        continue
      fi
      _sc_ports=$(parse_ports "$ANSWER")
      case $? in
        0)
          MODE=ports
          PORTS=$_sc_ports
          return 0
          ;;
        2) say_err "一次最多 30 个端口。要封更多就选整台机器。" ;;
        *) say_err "端口不对。请输入 1 到 65535 的数字，例如 80,443。" ;;
      esac
    done
  done
}

show_plan() {
  summarize_list "$1"
  say ""
  say "即将生效："
  say "  名单：域名 $((N_DOMAIN + N_SUFFIX)) 个（其中整段后缀 $N_SUFFIX 个），IP / 网段 $N_IP 个"
  if [ "$FW_BACKEND" = none ]; then
    say "  方式：只拦域名。这台机器（包括你搭的节点）查不到这些域名，也就打不开这些网站和 App。"
    [ "$N_IP" -gt 0 ] && say "  名单里的 $N_IP 个 IP / 网段封不了。"
    [ "$MODE" = all ] || say "  只拦域名时分不了端口，这些域名在所有端口上都会拦。"
    return 0
  fi
  say "  范围：$(scope_text "$MODE" "$PORTS")"
  if [ "$MODE" = all ]; then
    say "  域名的解析会被拦住，它们现在解析到的 IP 也会封掉。共用同一个 IP 的网站可能被误伤。"
  else
    say "  域名会先解析成 IP，只在这些端口上封。共用同一个 IP 的网站，这些端口也会连不上。"
  fi
  say "  只拦这台机器自己发出去的连接，包括代理程序替用户发出的连接。"
  say "  你的 SSH 来源、本机地址和本机用的 DNS 服务器会自动躲开。"
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

# 解析域名、写防火墙、装开机自启。$1 = setup（可以装软件）或 refresh。
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
  rebuild_ips "${1:-setup}"
  if [ ! -s "$CFG/v4" ] && [ ! -s "$CFG/v6" ] && [ "$(cat "$CFG/dns.method")" = none ]; then
    [ "$FW_BACKEND" = none ] && die "这台机器只能拦域名，但名单里没有域名（IP / 网段封不了）。"
    die "没有可以封的地址。按端口封域名时，要先能解析出 IP。"
  fi
  load_rules 1 || exit 1
  printf '%s\n' 1 >"$CFG/enabled"
  write_status
  # 定时刷新时不用每次重写开机服务。
  [ "${1:-setup}" = setup ] && install_persistence
  return 0
}

# apply_changes 名单方式 合并后的名单：写进配置并生效。
# 名单方式：new 换一套、append 追加、delete 删掉标记的、keep 名单不变。
# 失败时把配置和规则都恢复成原来的样子。
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
        rm -rf "$_ac_d"
      done <"$WORKDIR/del.list"
      : >"$WORKDIR/del.list"
      ;;
  esac
  [ -n "${2:-}" ] && cat "$2" >"$CFG/list.txt"
  printf '%s\n' "$MODE" >"$CFG/mode"
  printf '%s\n' "$PORTS" >"$CFG/ports"
  # 放进子 shell：里面任何一步 die，都只退出子 shell，这里接着恢复。
  if (activate setup); then
    if [ "$(cat "$CFG/backend" 2>/dev/null)" = none ]; then
      say_ok "已经生效（只拦域名）。"
      say "  如果用节点还能打开名单里的网站，重启一下节点程序，让它重新读这台机器的 DNS 设置。"
    else
      say_ok "已经生效。重启后会自动封上，名单里有域名时每 6 小时重新解析一次。"
    fi
    return 0
  fi
  say_err "没有生效，正在恢复原来的设置……"
  hosts_clear
  dnsmasq_clear
  cfg_restore
  if [ "$HAD_CFG" = 1 ] && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
    PROBED=0
    (load_rules 1) >/dev/null 2>&1 || true
  else
    remove_firewall
  fi
  say_info "已恢复成修改前的样子。"
  return 1
}

confirm_or_cancel() {
  [ "${OPT_YES:-0}" = 1 ] && return 0
  if ask_yn "确认生效？[y/N]: " n; then
    return 0
  fi
  say_info "已取消，什么都没改。"
  return 1
}

#----------------------------------------------------------------------
# 状态
#----------------------------------------------------------------------

write_status() {
  [ -n "${OS_PRETTY:-}" ] || detect_os
  _ws_method=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  summarize_list "$CFG/list.txt"
  {
    if [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
      printf '%s\n' "状态：开着"
    else
      printf '%s\n' "状态：关着"
    fi
    printf '系统：%s\n' "${OS_PRETTY:-未知}"
    if [ "$(cat "$CFG/backend" 2>/dev/null)" = none ]; then
      printf '%s\n' "方式：只拦域名（这台机器不能改防火墙，所有端口都拦）"
    else
      printf '范围：%s\n' "$(scope_text "$(cat "$CFG/mode" 2>/dev/null)" "$(cat "$CFG/ports" 2>/dev/null)")"
    fi
    printf '名单：域名 %s 个（其中整段后缀 %s 个），IP / 网段 %s 个\n' "$((N_DOMAIN + N_SUFFIX))" "$N_SUFFIX" "$N_IP"
    source_dirs saved >"$WORKDIR/status.idx"
    _ws_i=0
    while IFS= read -r _ws_d; do
      _ws_i=$((_ws_i + 1))
      show_source_line "$_ws_i" "$_ws_d"
    done <"$WORKDIR/status.idx"
    if [ "$(cat "$CFG/backend" 2>/dev/null)" = none ]; then
      printf '%s\n' "IP / 网段：封不了（这台机器不能改防火墙）"
    else
      printf '实际封住的地址：IPv4 %s 条，IPv6 %s 条\n' "$(count_lines "$CFG/v4")" "$(count_lines "$CFG/v6")"
    fi
    case $_ws_method in
      string) printf '%s\n' "域名拦截：拦发往 53 端口的域名查询，不改本机 DNS 设置" ;;
      dnsmasq) printf '%s\n' "域名拦截：dnsmasq 把这些域名回成“不存在”" ;;
      hosts) printf '%s\n' "域名拦截：写入 /etc/hosts，子域名拦不住" ;;
      *) printf '%s\n' "域名拦截：没有，只封 IP" ;;
    esac
    printf '版本：%s\n' "$VERSION"
  } >"$CFG/status.txt"
}

show_status() {
  if [ ! -f "$CFG/status.txt" ]; then
    say_info "这台机器还没有封禁记录。"
    return 0
  fi
  cat "$CFG/status.txt"
  [ "$(id -u)" = 0 ] && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ] || return 0
  if [ "$(cat "$CFG/backend" 2>/dev/null)" = none ]; then
    [ "$(cat "$CFG/dns.method" 2>/dev/null)" = none ] && return 0
    if rules_live; then
      say "域名拦截：在运行"
    else
      say_warn "域名拦截没在运行（机器或容器重启过？）。运行 vps-fengjin on 重新生效。"
    fi
  elif [ -s "$CFG/v4" ] || [ -s "$CFG/v6" ] || [ "$(cat "$CFG/dns.method" 2>/dev/null)" = string ]; then
    if rules_live; then
      say "防火墙规则：在"
    else
      say_warn "防火墙规则不在了，可能被别的防火墙重载清掉。运行 vps-fengjin refresh 重新封上。"
    fi
  fi
}

#----------------------------------------------------------------------
# 交互流程
#----------------------------------------------------------------------

intro() {
  [ -n "${OS_PRETTY:-}" ] || detect_os
  _in_kb=$(mem_total_kb)
  say ""
  say "这个脚本让这台服务器访问不了你给出的域名、IP 或网段。"
  say "系统：$OS_PRETTY    内存：$([ "$_in_kb" -gt 0 ] && echo "$((_in_kb / 1024)) MB" || echo 未知)"
  say ""
  say "名单支持这些写法，可以混着写："
  say "  example.com    .example.com    *.example.com    1.2.3.4    1.2.3.0/24"
  say "  DOMAIN-SUFFIX,example.com    IP-CIDR,1.2.3.0/24    0.0.0.0 example.com    ||example.com^"
  say "  Clash 的 YAML 名单（payload:）"
  say ""
  say "用法很简单：加名单 → 确认。生效后，这台机器（包括你在上面搭的节点）"
  say "就打不开名单里的网站和 App 了。"
}

# 第一次设置，或换一套新名单。
# 第一次设置不问范围，直接封整台机器：新手最容易在这里把节点端口当成目标端口填进去。
# 换一套名单时沿用原来的范围。要改范围去菜单里的“修改封禁范围”。
flow_new() {
  say_step "检查这台机器"
  fw_precheck
  say_step "第 1 步：添加名单"
  collect_sources new
  merge_sources "$WORKDIR/merged.txt"
  MODE=$(cat "$CFG/mode" 2>/dev/null)
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  [ "$MODE" = ports ] || { MODE=all; PORTS=; }
  say_step "第 2 步：确认"
  show_plan "$WORKDIR/merged.txt"
  confirm_or_cancel || return 0
  apply_changes new "$WORKDIR/merged.txt"
}

flow_append() {
  say_step "追加名单"
  if ! collect_sources append; then
    say_info "没有追加新名单。"
    return 0
  fi
  merge_sources "$WORKDIR/merged.txt"
  MODE=$(cat "$CFG/mode")
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  fw_precheck
  show_plan "$WORKDIR/merged.txt"
  confirm_or_cancel || return 0
  apply_changes append "$WORKDIR/merged.txt"
}

flow_manage() {
  : >"$WORKDIR/del.list"
  manage_sources saved
  [ -s "$WORKDIR/del.list" ] || return 0
  _fm_n=$(count_lines "$WORKDIR/del.list")
  if [ -z "$(source_dirs all)" ]; then
    if ask_yn "名单全部删掉的话，封禁会关闭、名单清空。确定吗？[y/N]: " n; then
      disable_all
      remove_persistence
      rm -rf "$CFG/sources" "$CFG/list.txt" "$CFG/status.txt" "$CFG/v4" "$CFG/v6" \
        "$CFG/dns.list" "$CFG/resolved.last"
      printf '%s\n' 0 >"$CFG/enabled"
      say_ok "已清空。再运行 vps-fengjin 可以重新设置。"
      exit 0
    fi
    : >"$WORKDIR/del.list"
    say_info "没有删除。"
    return 0
  fi
  if ! ask_yn "删除 $_fm_n 份名单，并用剩下的名单重新生效？[Y/n]: " y; then
    : >"$WORKDIR/del.list"
    say_info "没有删除。"
    return 0
  fi
  merge_sources "$WORKDIR/merged.txt"
  MODE=$(cat "$CFG/mode")
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  apply_changes delete "$WORKDIR/merged.txt"
}

flow_scope() {
  fw_precheck
  if [ "$FW_BACKEND" = none ]; then
    say_info "这台机器只能拦域名，分不了端口，没有范围可改。"
    return 0
  fi
  ask_scope "$(cat "$CFG/mode")" "$(cat "$CFG/ports" 2>/dev/null)"
  show_plan "$CFG/list.txt"
  confirm_or_cancel || return 0
  apply_changes keep ""
}

flow_reapply() {
  MODE=$(cat "$CFG/mode")
  PORTS=$(cat "$CFG/ports" 2>/dev/null)
  apply_changes keep ""
}

cmd_off() {
  if [ ! -d "$CFG" ]; then
    say_info "这台机器还没有封禁记录。"
    return 0
  fi
  printf '%s\n' 0 >"$CFG/enabled"
  disable_all
  [ -f "$CFG/list.txt" ] && write_status
  say_ok "已关闭，名单还在。要再打开：vps-fengjin on"
}

cmd_purge() {
  # dnsmasq_clear 要读 $CFG 里的记录，必须在删目录之前。
  disable_all
  remove_persistence
  if [ -f "$CFG/dnsmasq.confdir" ] && [ -f /etc/dnsmasq.conf ]; then
    grep -vxF 'conf-dir=/etc/dnsmasq.d/,*.conf' /etc/dnsmasq.conf >"$WORKDIR/dnsmasq.conf.new"
    cat "$WORKDIR/dnsmasq.conf.new" >/etc/dnsmasq.conf
  fi
  if [ -f /swapfile-vps-fengjin ]; then
    swapoff /swapfile-vps-fengjin 2>/dev/null
    rm -f /swapfile-vps-fengjin
    if grep -q '/swapfile-vps-fengjin' /etc/fstab 2>/dev/null; then
      grep -v '/swapfile-vps-fengjin' /etc/fstab >"$WORKDIR/fstab.new"
      cat "$WORKDIR/fstab.new" >/etc/fstab
    fi
  fi
  rm -rf "$CFG"
  rm -f "$BIN_DEFAULT" /usr/sbin/vps-fengjin
  say_ok "已彻底删除。"
}

menu() {
  while :; do
    say ""
    say "===================="
    show_status
    say "===================="
    say "  1) 重新生效（重新解析域名，换上当前版本的规则）"
    say "  2) 追加名单"
    say "  3) 管理名单（查看、改名、删除）"
    say "  4) 换一套新名单"
    say "  5) 修改封禁范围（高级，一般用不到）"
    say "  6) 关闭封禁，名单留着"
    say "  7) 彻底删除"
    say "  0) 退出"
    ask_pick "请选择 [0]: " 0 1 2 3 4 5 6 7 0
    case $ANSWER in
      1) flow_reapply ;;
      2) flow_append ;;
      3) flow_manage ;;
      4) flow_new ;;
      5) flow_scope ;;
      6)
        if [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
          cmd_off
        else
          say_info "封禁本来就是关着的。选 1 可以重新打开。"
        fi
        ;;
      7)
        if ask_yn "彻底删除名单、规则和开机自启？[y/N]: " n; then
          cmd_purge
          return 0
        fi
        say_info "已取消。"
        ;;
      0) return 0 ;;
    esac
  done
}

#----------------------------------------------------------------------
# 不提问的运行方式：sh install.sh -l 名单 [-p 端口 | -a] [--replace] -y
#----------------------------------------------------------------------

unattended() {
  if [ -s "$WORKDIR/opt.lists" ]; then
    PENDING=$WORKDIR/sources
    rm -rf "$PENDING"
    mkdir -p "$PENDING"
    while IFS= read -r _un_src; do
      add_from "$_un_src" || die "名单「$_un_src」没有加进去，什么都没改。"
    done <"$WORKDIR/opt.lists"
    _un_how=append
    if [ ! -f "$CFG/list.txt" ] || [ "${OPT_REPLACE:-0}" = 1 ]; then
      _un_how=new
    fi
  else
    [ -f "$CFG/list.txt" ] || die "还没有名单。用 -l 指定名单网址或文件，例如：sh install.sh -l https://example.com/list.txt -y"
    _un_how=keep
  fi
  if [ "$_un_how" = new ]; then
    # 换一套：合并时不带原来的名单。
    source_dirs pending | while IFS= read -r _un_d; do cat "$_un_d/list"; done \
      | LC_ALL=C sort -u >"$WORKDIR/merged.txt"
    cap_list "$WORKDIR/merged.txt"
  elif [ "$_un_how" = append ]; then
    merge_sources "$WORKDIR/merged.txt"
  else
    cp "$CFG/list.txt" "$WORKDIR/merged.txt"
  fi
  MODE=${OPT_MODE:-$(cat "$CFG/mode" 2>/dev/null)}
  [ -n "$MODE" ] || MODE=all
  if [ "$MODE" = ports ]; then
    PORTS=${OPT_PORTS:-$(cat "$CFG/ports" 2>/dev/null)}
    [ -n "$PORTS" ] || die "按端口封需要用 -p 指定端口。"
  else
    PORTS=
  fi
  fw_precheck
  show_plan "$WORKDIR/merged.txt"
  confirm_or_cancel || exit 0
  if [ "$_un_how" = keep ]; then
    apply_changes keep ""
  else
    apply_changes "$_un_how" "$WORKDIR/merged.txt"
  fi
}

parse_opts() {
  : >"$WORKDIR/opt.lists"
  OPT_GIVEN=0
  while [ $# -gt 0 ]; do
    case $1 in
      -l|--list)
        [ $# -ge 2 ] || die "$1 后面要跟名单网址或文件路径。"
        printf '%s\n' "$2" >>"$WORKDIR/opt.lists"
        shift 2
        ;;
      --list=*)
        printf '%s\n' "${1#--list=}" >>"$WORKDIR/opt.lists"
        shift
        ;;
      -p|--ports)
        [ $# -ge 2 ] || die "$1 后面要跟端口，例如 80,443。"
        OPT_PORTS=$(parse_ports "$2") || die "端口不对：$2（1 到 65535，最多 30 个）"
        OPT_MODE=ports
        shift 2
        ;;
      --ports=*)
        OPT_PORTS=$(parse_ports "${1#--ports=}") || die "端口不对：${1#--ports=}"
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
  sh install.sh                     按提示设置；已经设置过就打开菜单
  sh install.sh [选项]               不用菜单，按参数设置
  vps-fengjin status                查看
  vps-fengjin refresh               域名重新解析后再封一次
  vps-fengjin on | off              打开 / 关闭，名单留着
  vps-fengjin purge                 彻底删除
  sh install.sh check 文件           只检查名单，不改防火墙

选项：
  -l, --list 名单    名单网址或文件路径，可以写多次；写 - 表示从标准输入读
  -a, --all          封整台机器（默认）
  -p, --ports 端口   只封这些目标端口，例如 80,443
      --replace      换掉原来的名单（默认是追加到原来的名单里）
  -y, --yes          不再确认，直接生效

例子：
  sh install.sh -l https://example.com/block.list -y
  sh install.sh -l /root/a.txt -l /root/b.txt -p 443 --replace -y
EOF
}

#----------------------------------------------------------------------
# 入口
#----------------------------------------------------------------------

require_root() {
  [ "$(id -u)" = 0 ] || die "请用 root 运行。例如：sudo sh install.sh"
}

require_linux() {
  [ "$(uname -s)" = Linux ] || die "请在 Linux 服务器上运行。"
}

take_lock() {
  LOCKDIR=/tmp/vps-fengjin.lock
  [ -d /run ] && [ -w /run ] && LOCKDIR=/run/vps-fengjin.lock
  for _tl in 1 2; do
    if mkdir "$LOCKDIR" 2>/dev/null; then
      echo $$ >"$LOCKDIR/pid"
      LOCKED=1
      return 0
    fi
    _tl_old=$(cat "$LOCKDIR/pid" 2>/dev/null)
    if [ -n "$_tl_old" ] && kill -0 "$_tl_old" 2>/dev/null; then
      return 1
    fi
    rm -rf "$LOCKDIR"
  done
  return 1
}

cleanup() {
  [ -n "${WORKDIR:-}" ] && [ "$WORKDIR" != / ] && rm -rf "$WORKDIR"
  [ "${LOCKED:-0}" = 1 ] && rm -rf "${LOCKDIR:-/nonexistent}"
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
  trap 'exit 130' INT TERM
}

# 设置类命令都要的准备：root、Linux、锁、把自己装成 vps-fengjin 命令。
prepare_setup() {
  require_linux
  require_root
  take_lock || die "另一个 vps-fengjin 任务正在跑，等它结束再试。"
  detect_os
  _pr_old=$(sed -n 's/^VERSION=//p' "$(installed_bin)" 2>/dev/null | head -n 1)
  install_self
  if [ -n "$_pr_old" ] && [ "$_pr_old" != "$VERSION" ]; then
    say_ok "已从 $_pr_old 更新到 $VERSION，名单和设置都还在。"
    UPGRADED=1
  fi
  migrate_sources
  [ -f "$CFG/mode" ] && [ -f "$CFG/list.txt" ] && write_status
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
      [ -f "$CFG/status.txt" ] && say "" && say "改名单或范围：vps-fengjin    关闭：vps-fengjin off"
      ;;
    check)
      [ -n "${2:-}" ] || die "用法：sh install.sh check 名单文件"
      [ -f "$2" ] || die "找不到文件：$2"
      fengjin_awk classify <"$2" >"$WORKDIR/check.all"
      summarize_list "$WORKDIR/check.all"
      say "域名 $N_DOMAIN 个，整段后缀 $N_SUFFIX 个，IP / 网段 $N_IP 个，跳过 $N_BAD 行"
      show_bads "$WORKDIR/check.all"
      ;;
    apply-rules)
      # 开机时用：按保存的结果直接封，不解析、不装软件、不改 DNS 设置（那些本来就留着）。
      require_linux
      require_root
      [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ] || exit 0
      take_lock || exit 0
      detect_os
      load_rules 0
      ;;
    refresh|apply)
      require_linux
      require_root
      [ -f "$CFG/list.txt" ] || die "还没有名单。"
      if [ "$(cat "$CFG/enabled" 2>/dev/null)" != 1 ]; then
        say_info "封禁是关着的，没有刷新。"
        exit 0
      fi
      take_lock || { say_warn "另一个 vps-fengjin 任务正在跑，这次跳过。"; exit 0; }
      detect_os
      activate refresh
      say_ok "已刷新：IPv4 $(count_lines "$CFG/v4") 条，IPv6 $(count_lines "$CFG/v6") 条。"
      ;;
    on)
      require_linux
      require_root
      [ -f "$CFG/list.txt" ] || die "还没有名单。运行 sh install.sh 设置。"
      take_lock || die "另一个 vps-fengjin 任务正在跑。"
      detect_os
      flow_reapply || exit 1
      ;;
    off)
      require_linux
      require_root
      take_lock || die "另一个 vps-fengjin 任务正在跑。"
      cmd_off
      ;;
    purge)
      require_linux
      require_root
      take_lock || die "另一个 vps-fengjin 任务正在跑。"
      cmd_purge
      ;;
    ''|-*)
      parse_opts "$@"
      prepare_setup
      if [ "$OPT_GIVEN" = 1 ]; then
        unattended
      elif [ -f "$CFG/list.txt" ] && [ -f "$CFG/mode" ]; then
        if [ "${UPGRADED:-0}" = 1 ] && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
          if ask_yn "现在用新版本重新生效一次吗？[Y/n]: " y; then
            flow_reapply
          fi
        fi
        menu
      else
        intro
        if flow_new && [ "$(cat "$CFG/enabled" 2>/dev/null)" = 1 ]; then
          say ""
          show_status
          say ""
          say "以后运行 vps-fengjin 可以追加名单、改范围、关闭；vps-fengjin status 查看。"
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
