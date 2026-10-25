#!/bin/sh
# vps-fengjin-onekey-begin
#======================================================================
# 封禁一台服务器访问指定的域名、IP、网段。
#
# 在新机器上运行一次。脚本自己认出系统，问你名单从哪来，
# 再问是封一个目标端口、多个目标端口，还是整台机器。
# 64MB 内存的小鸡也可以跑：不装大软件，名单很大时才加一点交换空间。
#
#   sh install.sh            按提示设置
#   sh install.sh status     查看
#   sh install.sh refresh    域名重新解析后再封一次
#   sh install.sh apply-rules  只按已经保存的结果封，不重新解析
#   sh install.sh off        关闭，名单留着
#   sh install.sh purge      彻底删除
#   sh install.sh check 文件  只检查名单，不改防火墙
#======================================================================

VERSION=1.0.0
CFG=/etc/vps-fengjin
CHAIN=VPS_FENGJIN
SET4=vps_fengjin4
SET6=vps_fengjin6
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

say_ok()   { printf '%s\n' "${C_GREEN}✓ $*${C_NC}"; }
say_info() { printf '%s\n' "${C_BLUE}$*${C_NC}"; }
say_warn() { printf '%s\n' "${C_YELLOW}! $*${C_NC}"; }
say_err()  { printf '%s\n' "${C_RED}✗ $*${C_NC}" >&2; }
say_step() { printf '\n%s\n' "${C_YELLOW}>>> $*${C_NC}"; }
die()      { say_err "$*"; exit 1; }

#----------------------------------------------------------------------
# 纯判断。测试直接调用，不改系统。
# fengjin_awk 的第 1 个参数是模式：
#   classify / ports / wire / extract / overlap / rules / ipset / nft
#----------------------------------------------------------------------

fengjin_awk() {
  _mode=$1
  _peers=${2:-}
  _server=${3:-}
  _skip=${4:-}
  _plan=${5:-}
  _fam=${6:-4}
  _mp=${7:-1}
  _algo=${8:-bm}
  _rtcp=${9:-reset}
  _roth=${10:-reject}
  _ipset=${11:-1}
  LC_ALL=C awk \
    -v mode="$_mode" \
    -v peers="$_peers" \
    -v server="$_server" \
    -v skipfile="$_skip" \
    -v plan="$_plan" \
    -v fam="$_fam" \
    -v multiport="$_mp" \
    -v algo="$_algo" \
    -v reject_tcp="$_rtcp" \
    -v reject_other="$_roth" \
    -v have_ipset="$_ipset" '
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
    if (a[i] !~ /^[0-9]+$/) return 0
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
function v4_contains(net, ip,   a, base, bits, nb, ni, shift) {
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
  nb = ip4num(base)
  ni = ip4num(ip)
  if (bits == 0) return 1
  shift = 2 ^ (32 - bits)
  return int(nb / shift) == int(ni / shift)
}
function v6group_ok(g) {
  if (length(g) < 1 || length(g) > 4) return 0
  if (g !~ /^[0-9A-Fa-f]+$/) return 0
  return 1
}
function is_ipv6(s,   n, i, left, right, lc, rc, lg, rg) {
  if (s == "") return 0
  if (s ~ /[^0-9A-Fa-f:]/) return 0
  if (split(s, parts, "::") > 2) return 0
  if (index(s, "::") == 0) {
    n = split(s, lg, ":")
    if (n != 8) return 0
    for (i = 1; i <= n; i++) if (!v6group_ok(lg[i])) return 0
    return 1
  }
  n = split(s, parts, "::")
  left = parts[1]
  right = parts[2]
  lc = 0
  rc = 0
  if (left != "") {
    lc = split(left, lg, ":")
    for (i = 1; i <= lc; i++) if (!v6group_ok(lg[i])) return 0
  }
  if (right != "") {
    rc = split(right, rg, ":")
    for (i = 1; i <= rc; i++) if (!v6group_ok(rg[i])) return 0
  }
  if (lc + rc > 7) return 0
  return 1
}
function pad4(h) {
  h = tolower(h)
  while (length(h) < 4) h = "0" h
  return h
}
function v6_expand(s,   n, i, left, right, lc, rc, lg, rg, zeros, out) {
  if (!is_ipv6(s)) return ""
  out = ""
  if (index(s, "::") == 0) {
    n = split(s, lg, ":")
    for (i = 1; i <= n; i++) out = out pad4(lg[i])
    if (length(out) != 32) return ""
    return out
  }
  n = split(s, parts, "::")
  left = parts[1]
  right = parts[2]
  lc = 0
  rc = 0
  if (left != "") lc = split(left, lg, ":")
  if (right != "") rc = split(right, rg, ":")
  zeros = 8 - lc - rc
  if (zeros < 0) return ""
  for (i = 1; i <= lc; i++) out = out pad4(lg[i])
  for (i = 1; i <= zeros; i++) out = out "0000"
  for (i = 1; i <= rc; i++) out = out pad4(rg[i])
  if (length(out) != 32) return ""
  return out
}
function hexval(c) {
  c = tolower(c)
  if (c >= "0" && c <= "9") return c + 0
  if (c == "a") return 10
  if (c == "b") return 11
  if (c == "c") return 12
  if (c == "d") return 13
  if (c == "e") return 14
  if (c == "f") return 15
  return -1
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
  if (nb < 0 || ni < 0) return 0
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
  if (e ~ /^0+$/) return 1
  if (e ~ /^0+1$/) return 1
  if (e ~ /^ff/) return 1
  if (e ~ /^fe[89ab]/) return 1
  return 0
}
function is_domain(s,   n, i, lab) {
  if (length(s) < 3 || length(s) > 253) return 0
  if (s !~ /^[A-Za-z0-9.-]+$/) return 0
  if (s ~ /(^|\.)\.|\.$|^\./) return 0
  n = split(s, lab, ".")
  if (n < 2) return 0
  for (i = 1; i <= n; i++) {
    if (length(lab[i]) < 1 || length(lab[i]) > 63) return 0
    if (lab[i] !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) return 0
  }
  # 顶级域不会是纯数字。hosts 名单里的 "0.0.0.0 0.0.0.0" 这类行不能当域名。
  if (lab[n] ~ /^[0-9]+$/) return 0
  return 1
}
function is_sink(s) {
  if (s == "0.0.0.0" || s == "127.0.0.1" || s == "::" || s == "::1" || s == "255.255.255.255") return 1
  return 0
}
function emit_name(kind, host) {
  host = tolower(trim(host))
  sub(/\.$/, "", host)
  if (substr(host, 1, 2) == "*.") {
    kind = "suffix"
    host = substr(host, 3)
  } else if (substr(host, 1, 1) == ".") {
    kind = "suffix"
    host = substr(host, 2)
  }
  if (!is_domain(host)) {
    bad("parse", host)
    return
  }
  print kind "\t" host
}
function emit_addr(s,   n, a, left, bits, net) {
  s = trim(s)
  if (index(s, "/") > 0) {
    n = split(s, a, "/")
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
      # 和 IPv4 一样把主机位清零。nft 的区间集合不接受带主机位的网段。
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
function do_classify(   s, f, n, kind, host) {
  s = trim($0)
  if (s == "" || substr(s, 1, 1) == "#" || substr(s, 1, 1) == "!") return
  if (substr(s, 1, 2) == "@@") return
  sub(/[ \t]+#.*/, "", s)
  s = trim(s)
  if (s == "") return
  if (s ~ /^address=\//) {
    n = split(s, f, "/")
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
    if (kind ~ /^[A-Z0-9_-]+$/) { bad("unsupported", s); return }
  }
  s = strip_url(s)
  if (substr(s, 1, 1) == "[") {
    if (match(s, /^\[[0-9A-Fa-f:]+\]/)) {
      host = substr(s, 2, RLENGTH - 2)
      emit_addr(host)
      return
    }
  }
  emit_addr_or_name(s)
}
function do_ports(   n, i, p, c, arr, j, t, out) {
  gsub(/，/, ",", $0)
  gsub(/、/, ",", $0)
  n = split($0, a, /[ \t,]+/)
  c = 0
  for (i = 1; i <= n; i++) {
    p = a[i]
    if (p == "") continue
    if (p !~ /^[0-9]+$/ || (p + 0) < 1 || (p + 0) > 65535) exit 1
    if (length(p) > 1 && substr(p, 1, 1) == "0") exit 1
    if (seen[p + 0]) continue
    seen[p + 0] = 1
    c++
    arr[c] = p + 0
  }
  if (c == 0) exit 1
  if (c > 30) exit 2
  for (i = 1; i <= c; i++) {
    for (j = i + 1; j <= c; j++) {
      if (arr[j] < arr[i]) {
        t = arr[i]
        arr[i] = arr[j]
        arr[j] = t
      }
    }
  }
  out = ""
  for (i = 1; i <= c; i++) {
    if (i > 1) out = out ","
    out = out arr[i]
  }
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
function emit_ip(s) {
  gsub(/^[\[\(]+/, "", s)
  gsub(/[\]\)\.,;]+$/, "", s)
  if (s ~ /^[0-9.]+:[0-9]+$/) sub(/:[0-9]+$/, "", s)
  if (s ~ /#[0-9]+$/) sub(/#[0-9]+$/, "", s)
  if (!(is_ipv4(s) || is_ipv6(s))) return
  if (s == server || s == "0.0.0.0" || s == "127.0.0.1" || s == "::" || s == "::1") return
  if (seenip[s]++) return
  print s
}
function do_extract(   n, i, f) {
  n = split($0, f, /[ \t]+/)
  for (i = 1; i <= n; i++) emit_ip(f[i])
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
      if (v4_contains(val, p4[i])) {
        note_skip(val "\t" p4[i])
        return
      }
    }
  } else if (kind == "ip6" || kind == "net6") {
    for (i = 1; i <= npeers6; i++) {
      if (v6_contains(val, p6[i])) {
        note_skip(val "\t" p6[i])
        return
      }
    }
  }
  print kind "\t" val
}
function read_one(path,   line) {
  line = ""
  if ((getline line < path) > 0) {
    close(path)
    return line
  }
  close(path)
  return ""
}
function tcp_jump() {
  if (reject_tcp == "reset") return "REJECT --reject-with tcp-reset"
  return "DROP"
}
function oth_jump() {
  if (reject_other == "reject") return "REJECT"
  return "DROP"
}
function emit_all(mspec) {
  print "-A VPS_FENGJIN " mspec " -j " oth_jump()
}
function emit_ports(mspec, ports,   n, i, p, group, count) {
  if (ports == "") return
  n = split(ports, p, ",")
  if (multiport == "1") {
    group = ""
    count = 0
    for (i = 1; i <= n; i++) {
      if (p[i] == "") continue
      if (group == "") group = p[i]
      else group = group "," p[i]
      count++
      if (count == 15 || i == n) {
        print "-A VPS_FENGJIN " mspec " -p tcp -m multiport --dports " group " -j " tcp_jump()
        print "-A VPS_FENGJIN " mspec " -p udp -m multiport --dports " group " -j " oth_jump()
        group = ""
        count = 0
      }
    }
  } else {
    for (i = 1; i <= n; i++) {
      if (p[i] == "") continue
      print "-A VPS_FENGJIN " mspec " -p tcp --dport " p[i] " -j " tcp_jump()
      print "-A VPS_FENGJIN " mspec " -p udp --dport " p[i] " -j " oth_jump()
    }
  }
}
function emit_string(h) {
  print "-A VPS_FENGJIN -p udp --dport 53 -m string --hex-string |" h "| --algo " algo " -j " oth_jump()
  print "-A VPS_FENGJIN -p tcp --dport 53 -m string --hex-string |" h "| --algo " algo " -j " tcp_jump()
}
function render_rules(   mode_s, ports_s, method, list, setname, mspec, addr, line, h, c) {
  mode_s = read_one(plan "/mode")
  ports_s = read_one(plan "/ports")
  method = read_one(plan "/dns.method")
  if (fam == "6") {
    list = plan "/v6"
    setname = "vps_fengjin6"
  } else {
    list = plan "/v4"
    setname = "vps_fengjin4"
  }
  if (have_ipset == "1") {
    if ((getline addr < list) > 0 && addr != "") {
      close(list)
      mspec = "-m set --match-set " setname " dst"
      if (mode_s == "all") emit_all(mspec)
      else emit_ports(mspec, ports_s)
    } else close(list)
  } else {
    c = 0
    while ((getline addr < list) > 0) {
      if (addr == "") continue
      c++
      if (c > 1500) {
        print "ipset 不可用，只写入前 1500 条地址" > "/dev/stderr"
        break
      }
      mspec = "-d " addr
      if (mode_s == "all") emit_all(mspec)
      else emit_ports(mspec, ports_s)
    }
    close(list)
  }
  if (fam == "4" || fam == "6") {
    if (mode_s == "all" && method == "string" && algo != "" && algo != "none") {
      while ((getline line < (plan "/dns.list")) > 0) {
        if (line == "") continue
        h = wire_hex(line)
        if (h == "" || length(h) > 240) continue
        # 末尾带上 00 结束符：example.com 不会误拦 example.com.cn，子域名照样拦。
        emit_string(h "00")
      }
      close(plan "/dns.list")
    }
  }
}
function render_ipset(   list, name, family, n, line, maxe, hs) {
  if (fam == "6") {
    list = plan "/v6"
    name = "vps_fengjin6"
    family = "inet6"
  } else {
    list = plan "/v4"
    name = "vps_fengjin4"
    family = "inet"
  }
  n = 0
  while ((getline line < list) > 0) if (line != "") n++
  close(list)
  if (n == 0) exit 1
  maxe = n + 128
  if (maxe < 256) maxe = 256
  hs = 1024
  if (n > 4000) hs = 4096
  print "create " name " hash:net family " family " hashsize " hs " maxelem " maxe " -exist"
  print "flush " name
  while ((getline line < list) > 0) if (line != "") print "add " name " " line
  close(list)
}
function csv_join(path,   line, out, n) {
  out = ""
  n = 0
  while ((getline line < path) > 0) {
    if (line == "") continue
    n++
    if (out == "") out = line
    else out = out ", " line
  }
  close(path)
  joined_n = n
  return out
}
function nft_ports(ports,   n, i, p, out) {
  n = split(ports, p, ",")
  out = ""
  for (i = 1; i <= n; i++) {
    if (p[i] == "") continue
    if (out == "") out = p[i]
    else out = out ", " p[i]
  }
  return "{ " out " }"
}
function render_nft(   mode_s, ports_s, e4, e6) {
  mode_s = read_one(plan "/mode")
  ports_s = read_one(plan "/ports")
  e4 = csv_join(plan "/v4")
  n4 = joined_n
  e6 = csv_join(plan "/v6")
  n6 = joined_n
  print "table inet vpsfengjin {"
  if (n4 > 0) {
    print "  set block4 {"
    print "    type ipv4_addr"
    print "    flags interval"
    print "    auto-merge"
    print "    elements = { " e4 " }"
    print "  }"
  }
  if (n6 > 0) {
    print "  set block6 {"
    print "    type ipv6_addr"
    print "    flags interval"
    print "    auto-merge"
    print "    elements = { " e6 " }"
    print "  }"
  }
  print "  chain out {"
  print "    type filter hook output priority -50; policy accept;"
  if (mode_s == "all") {
    if (n4 > 0) print "    ip daddr @block4 reject"
    if (n6 > 0) print "    ip6 daddr @block6 reject"
  } else {
    if (n4 > 0) {
      print "    ip daddr @block4 tcp dport " nft_ports(ports_s) " reject"
      print "    ip daddr @block4 udp dport " nft_ports(ports_s) " reject"
    }
    if (n6 > 0) {
      print "    ip6 daddr @block6 tcp dport " nft_ports(ports_s) " reject"
      print "    ip6 daddr @block6 udp dport " nft_ports(ports_s) " reject"
    }
  }
  print "  }"
  print "}"
}
BEGIN {
  for (i = 1; i < 128; i++) ord[sprintf("%c", i)] = i
  npeers4 = 0
  npeers6 = 0
  if (mode == "rules") { render_rules(); exit }
  if (mode == "ipset") { render_ipset(); exit }
  if (mode == "nft") { render_nft(); exit }
  if (mode == "overlap" && peers != "") {
    while ((getline line < peers) > 0) {
      line = trim(line)
      if (line == "") continue
      if (is_ipv4(line)) { npeers4++; p4[npeers4] = line }
      else if (is_ipv6(line)) { npeers6++; p6[npeers6] = line }
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
'
}

parse_ports() {
  printf '%s\n' "$1" | fengjin_awk ports
}

#----------------------------------------------------------------------
# 系统、内存、软件源。只在真正安装时用。
#----------------------------------------------------------------------

detect_os() {
  PM=none
  if command -v apt-get >/dev/null 2>&1; then
    PM=apt
  elif command -v dnf >/dev/null 2>&1; then
    PM=dnf
  elif command -v yum >/dev/null 2>&1; then
    PM=yum
  elif command -v apk >/dev/null 2>&1; then
    PM=apk
  elif command -v pacman >/dev/null 2>&1; then
    PM=pacman
  elif command -v zypper >/dev/null 2>&1; then
    PM=zypper
  elif command -v opkg >/dev/null 2>&1; then
    PM=opkg
  fi
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
  awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null
}

# 名单上限。临时文件放在硬盘上，名单大小本身不占内存；
# 真正吃内存的是 dnsmasq 里的域名，每条大约一百字节。
# 64MB 小鸡放 10 万条，大一些的机器可以吃下整份去广告名单（常见的有 30 万条）。
list_limits() {
  kb=$(mem_total_kb)
  case ${kb:-} in
    ''|*[!0-9]*) kb=0 ;;
  esac
  LIST_MAX_MB=32
  LIST_MAX_BYTES=$((LIST_MAX_MB * 1048576))
  if [ "$kb" -gt 196608 ]; then
    LIST_MAX_ITEMS=500000
  else
    LIST_MAX_ITEMS=100000
  fi
}

# 临时目录。很多系统的 /tmp 是内存盘，几 MB 的名单复制几份就能把小鸡挤爆，
# 所以尽量放到硬盘上。
pick_tmpdir() {
  for d in "${TMPDIR:-}" /var/tmp /root /tmp; do
    [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] || continue
    fs=$(df -P "$d" 2>/dev/null | awk 'NR == 2 { print $1 }')
    case $fs in
      tmpfs|ramfs|none) [ "$d" = /tmp ] || continue ;;
    esac
    printf '%s\n' "$d"
    return 0
  done
  printf '%s\n' /tmp
}

lowmem_prepare() {
  kb=$(mem_total_kb)
  [ -n "$kb" ] || return 0
  if [ "$kb" -gt 196608 ]; then
    return 0
  fi
  say_info "内存大约 $((kb / 1024)) MB。按小鸡处理：允许超卖，磁盘够的话加 64MB 交换。"
  sysctl -w vm.overcommit_memory=1 >/dev/null 2>&1 || true
  if ! awk 'NR>1 { found=1 } END { exit found ? 0 : 1 }' /proc/swaps 2>/dev/null; then
    free_kb=$(df -Pk / 2>/dev/null | awk 'NR==2 { print $4 }')
    case ${free_kb:-} in
      ''|*[!0-9]*) free_kb=0 ;;
    esac
    if [ "$free_kb" -ge 180000 ]; then
      make_swap || say_warn "交换空间没加上，继续。名单特别大时可能会紧。"
    else
      say_warn "磁盘剩余不多，不加交换空间。"
    fi
  fi
  sync
  echo 3 >/proc/sys/vm/drop_caches 2>/dev/null || true
}

make_swap() {
  f=/swapfile-vps-fengjin
  if [ -f "$f" ]; then
    grep -q '/swapfile-vps-fengjin' /proc/swaps 2>/dev/null && return 0
    swapon "$f" 2>/dev/null && return 0
    rm -f "$f"
  fi
  if command -v fallocate >/dev/null 2>&1 && fallocate -l 64M "$f" 2>/dev/null; then
    :
  else
    dd if=/dev/zero of="$f" bs=1048576 count=64 >/dev/null 2>&1 || return 1
  fi
  # 容器里常常不让开交换。失败就把文件删掉，别在小硬盘上留 64MB 垃圾。
  if ! chmod 600 "$f" || ! mkswap "$f" >/dev/null 2>&1 || ! swapon "$f" 2>/dev/null; then
    rm -f "$f"
    return 1
  fi
  if [ -f /etc/fstab ]; then
    if ! grep -q '/swapfile-vps-fengjin' /etc/fstab 2>/dev/null; then
      printf '\n/swapfile-vps-fengjin none swap sw 0 0\n' >>/etc/fstab
    fi
  else
    printf '/swapfile-vps-fengjin none swap sw 0 0\n' >/etc/fstab
  fi
  say_ok "已加上 64MB 交换空间"
}

pm_install() {
  pkg=$1
  case ${PM:-none} in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      if [ "${APT_UPDATED:-0}" != 1 ]; then
        apt-get update -qq || say_warn "软件源没有完全更新，仍尝试安装。"
        APT_UPDATED=1
      fi
      apt-get install -y --no-install-recommends \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        "$pkg"
      ;;
    apk) apk add --no-cache "$pkg" ;;
    dnf) dnf install -y "$pkg" ;;
    yum) yum install -y "$pkg" ;;
    pacman) pacman -Sy --noconfirm "$pkg" ;;
    zypper) zypper --non-interactive install "$pkg" ;;
    opkg)
      if [ "${OPKG_UPDATED:-0}" != 1 ]; then
        opkg update || say_warn "opkg 源更新失败，仍尝试安装。"
        OPKG_UPDATED=1
      fi
      opkg install "$pkg"
      ;;
    *) return 1 ;;
  esac
}

need_cmd() {
  cmd=$1
  shift
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  for pkg in "$@"; do
    say_info "缺少 $cmd，尝试安装 $pkg"
    if pm_install "$pkg" && command -v "$cmd" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

#----------------------------------------------------------------------
# 防火墙探测和生效。只拦本机发出去的连接（OUTPUT）。
# 代理程序替用户连出去，也算本机发出。
#----------------------------------------------------------------------

probe_firewall() {
  HAVE_IPSET=0
  HAVE_MULTIPORT=0
  HAVE_STRING=0
  STRING_ALGO=none
  REJECT_TCP=drop
  REJECT_OTHER=drop
  FW_BACKEND=none
  modprobe ip_tables 2>/dev/null || true
  modprobe iptable_filter 2>/dev/null || true
  modprobe ip_set 2>/dev/null || true
  modprobe xt_set 2>/dev/null || true
  modprobe xt_string 2>/dev/null || true
  modprobe xt_multiport 2>/dev/null || true
  modprobe nf_tables 2>/dev/null || true
  if command -v iptables >/dev/null 2>&1; then
    iptables -F VPS_FENGJIN_T 2>/dev/null || true
    iptables -X VPS_FENGJIN_T 2>/dev/null || true
    if iptables -N VPS_FENGJIN_T >/dev/null 2>&1; then
      FW_BACKEND=iptables
      if iptables -A VPS_FENGJIN_T -j REJECT >/dev/null 2>&1; then
        REJECT_OTHER=reject
      fi
      iptables -F VPS_FENGJIN_T 2>/dev/null || true
      if iptables -A VPS_FENGJIN_T -p tcp -j REJECT --reject-with tcp-reset >/dev/null 2>&1; then
        REJECT_TCP=reset
      fi
      iptables -F VPS_FENGJIN_T 2>/dev/null || true
      if iptables -A VPS_FENGJIN_T -p tcp -m multiport --dports 80 -j RETURN >/dev/null 2>&1; then
        HAVE_MULTIPORT=1
      fi
      iptables -F VPS_FENGJIN_T 2>/dev/null || true
      if command -v ipset >/dev/null 2>&1; then
        ipset destroy vps_fengjin_t 2>/dev/null || true
        if ipset create vps_fengjin_t hash:net family inet maxelem 16 >/dev/null 2>&1; then
          if iptables -A VPS_FENGJIN_T -m set --match-set vps_fengjin_t dst -j RETURN >/dev/null 2>&1; then
            HAVE_IPSET=1
          fi
          iptables -F VPS_FENGJIN_T 2>/dev/null || true
          ipset destroy vps_fengjin_t 2>/dev/null || true
        fi
      fi
      iptables -F VPS_FENGJIN_T 2>/dev/null || true
      for _algo in bm kmp; do
        if iptables -A VPS_FENGJIN_T -m string --hex-string "|61|" --algo "$_algo" -j RETURN >/dev/null 2>&1; then
          HAVE_STRING=1
          STRING_ALGO=$_algo
          break
        fi
        iptables -F VPS_FENGJIN_T 2>/dev/null || true
      done
      iptables -F VPS_FENGJIN_T 2>/dev/null || true
      iptables -X VPS_FENGJIN_T 2>/dev/null || true
    fi
  fi
  if [ "$FW_BACKEND" = none ] && command -v nft >/dev/null 2>&1; then
    if nft list tables >/dev/null 2>&1; then
      FW_BACKEND=nft
    fi
  fi
}

ensure_firewall() {
  detect_os
  lowmem_prepare
  if ! command -v iptables >/dev/null 2>&1; then
    need_cmd iptables iptables || true
  fi
  if ! command -v ipset >/dev/null 2>&1; then
    need_cmd ipset ipset || true
  fi
  probe_firewall
  if [ "$FW_BACKEND" = none ] && ! command -v nft >/dev/null 2>&1; then
    need_cmd nft nftables nft || true
    probe_firewall
  fi
  if [ "$FW_BACKEND" = none ]; then
    die "这台机器不能改防火墙（iptables 和 nft 都不可用）。有些被切出来的小鸡没有这个权限。"
  fi
  printf '%s\n' "$FW_BACKEND" >"$CFG/backend"
  if [ "$FW_BACKEND" = iptables ]; then
    if [ "$HAVE_IPSET" = 1 ]; then
      say_ok "防火墙：iptables + ipset"
    else
      say_warn "有 iptables，但 ipset 不能用。地址一多会慢，最多写 1500 条。"
    fi
  else
    say_ok "防火墙：nftables"
  fi
}

collect_excludes() {
  out=$1
  : >"$out"
  set -- ${SSH_CONNECTION:-}
  [ -n "${1:-}" ] && printf '%s\n' "$1" >>"$out"
  set -- ${SSH_CLIENT:-}
  [ -n "${1:-}" ] && printf '%s\n' "$1" >>"$out"
  # 定时刷新没有 SSH 环境变量。把设置时的登录地址记下来，以后每次都躲开。
  if [ -s "$out" ] && [ -d "$CFG" ]; then
    cat "$out" "$CFG/ssh.peers" 2>/dev/null | LC_ALL=C sort -u | tail -n 20 >"$WORKDIR/ssh.peers"
    cat "$WORKDIR/ssh.peers" >"$CFG/ssh.peers"
  fi
  cat "$CFG/ssh.peers" >>"$out" 2>/dev/null || true
  if [ -r /proc/net/tcp ]; then
    awk 'function h2d(h,    i, v, c, d) {
      v = 0
      h = tolower(h)
      for (i = 1; i <= length(h); i++) {
        c = substr(h, i, 1)
        if (c >= "0" && c <= "9") d = c + 0
        else if (c == "a") d = 10
        else if (c == "b") d = 11
        else if (c == "c") d = 12
        else if (c == "d") d = 13
        else if (c == "e") d = 14
        else if (c == "f") d = 15
        else d = 0
        v = v * 16 + d
      }
      return v
    }
    NR > 1 && $4 == "01" {
      split($2, loc, ":")
      split($3, rem, ":")
      if (loc[2] != "0016") next
      h = rem[1]
      if (length(h) != 8) next
      printf "%d.%d.%d.%d\n", h2d(substr(h, 7, 2)), h2d(substr(h, 5, 2)), h2d(substr(h, 3, 2)), h2d(substr(h, 1, 2))
    }' /proc/net/tcp >>"$out" 2>/dev/null || true
  fi
  if command -v ip >/dev/null 2>&1; then
    ip -4 -o addr show scope global 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1 >>"$out" || true
    ip -6 -o addr show scope global 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1 >>"$out" || true
  fi
  if [ -s "$out" ]; then
    LC_ALL=C sort -u "$out" -o "$out"
  fi
}

apply_iptables_family() {
  fam=$1
  rules=$2
  bin=iptables
  if [ "$fam" = 6 ]; then
    bin=ip6tables
    command -v ip6tables >/dev/null 2>&1 || return 0
  fi
  if [ ! -s "$rules" ]; then
    return 0
  fi
  "$bin" -N "$CHAIN" 2>/dev/null || true
  "$bin" -F "$CHAIN" 2>/dev/null || true
  if [ -s "$rules" ]; then
    set -f
    while IFS= read -r rule; do
      [ -n "$rule" ] || continue
      # shell 把变量展开后的 | 当成普通参数，不会当成管道。
      # shellcheck disable=SC2086
      if ! "$bin" $rule; then
        set +f
        "$bin" -F "$CHAIN" 2>/dev/null || true
        say_err "规则没有加上：$rule"
        return 1
      fi
    done <"$rules"
    set +f
  fi
  if ! "$bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
    "$bin" -I OUTPUT 1 -j "$CHAIN" || return 1
  fi
  return 0
}

# 拦 DNS 查询的规则也会挡住脚本自己去解析名单里的域名。
# 刷新时先拿掉这几条，IP 规则留着；解析完 load_rules 会整套重新写上。
pause_dns_rules() {
  for bin in iptables ip6tables; do
    command -v "$bin" >/dev/null 2>&1 || continue
    # 按序号从后往前删，前面的序号不会变。
    nums=$("$bin" -S "$CHAIN" 2>/dev/null | awk '/^-A / { n++; if (/ -m string /) print n }' | sort -rn)
    for num in $nums; do
      "$bin" -D "$CHAIN" "$num" 2>/dev/null || true
    done
  done
}

remove_iptables_family() {
  fam=$1
  bin=iptables
  [ "$fam" = 6 ] && bin=ip6tables
  command -v "$bin" >/dev/null 2>&1 || return 0
  while "$bin" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
    "$bin" -D OUTPUT -j "$CHAIN" || break
  done
  "$bin" -F "$CHAIN" 2>/dev/null || true
  "$bin" -X "$CHAIN" 2>/dev/null || true
}

load_ipset_file() {
  body=$1
  [ -s "$body" ] || return 0
  ipset restore <"$body"
}

remove_firewall() {
  remove_iptables_family 4
  remove_iptables_family 6
  if command -v ipset >/dev/null 2>&1; then
    ipset destroy "$SET4" 2>/dev/null || true
    ipset destroy "$SET6" 2>/dev/null || true
  fi
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet vpsfengjin 2>/dev/null || true
  fi
}

ipv6_on() {
  [ -r /proc/net/if_inet6 ] || return 1
  if command -v sysctl >/dev/null 2>&1; then
    v=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || true)
    [ "$v" = 1 ] && return 1
  fi
  return 0
}

load_rules() {
  [ -f "$CFG/enabled" ] || return 0
  en=$(cat "$CFG/enabled" 2>/dev/null || echo 0)
  if [ "$en" != 1 ]; then
    remove_firewall
    hosts_clear
    dnsmasq_clear
    return 0
  fi
  [ -f "$CFG/mode" ] || die "还没有保存封禁范围。"
  probe_firewall
  [ "$FW_BACKEND" = none ] && die "现在用不了防火墙，规则没生效。"
  method=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  if [ "$method" = string ] && { [ "$HAVE_STRING" != 1 ] || [ "$FW_BACKEND" != iptables ]; }; then
    say_warn "当前防火墙不能按域名拦 DNS，改写入 /etc/hosts。"
    method=hosts
    printf '%s\n' hosts >"$CFG/dns.method"
  fi
  algo=$STRING_ALGO
  [ "$algo" = none ] && algo=bm
  do6=0
  ipv6_on && do6=1
  remove_firewall
  if [ "$FW_BACKEND" = iptables ]; then
    if [ "$HAVE_IPSET" = 1 ]; then
      if [ -s "$CFG/v4" ]; then
        fengjin_awk ipset "" "" "" "$CFG" 4 >"$WORKDIR/set4.txt" || die "IPv4 地址集没有生成。"
        load_ipset_file "$WORKDIR/set4.txt" || die "IPv4 地址集没有写进去。"
      fi
      if [ "$do6" = 1 ] && [ -s "$CFG/v6" ]; then
        fengjin_awk ipset "" "" "" "$CFG" 6 >"$WORKDIR/set6.txt" || die "IPv6 地址集没有生成。"
        load_ipset_file "$WORKDIR/set6.txt" || die "IPv6 地址集没有写进去。"
      fi
    fi
    fengjin_awk rules "" "" "" "$CFG" 4 "$HAVE_MULTIPORT" "$algo" "$REJECT_TCP" "$REJECT_OTHER" "$HAVE_IPSET" >"$WORKDIR/r4.txt"
    apply_iptables_family 4 "$WORKDIR/r4.txt" || return 1
    if [ "$do6" = 1 ]; then
      fengjin_awk rules "" "" "" "$CFG" 6 "$HAVE_MULTIPORT" "$algo" "$REJECT_TCP" "$REJECT_OTHER" "$HAVE_IPSET" >"$WORKDIR/r6.txt"
      apply_iptables_family 6 "$WORKDIR/r6.txt" || return 1
    fi
  else
    fengjin_awk nft "" "" "" "$CFG" >"$WORKDIR/rules.nft" || die "nft 规则没有生成。"
    nft -f "$WORKDIR/rules.nft" || die "nft 规则没有写进去。"
  fi
  if [ "$method" = hosts ]; then
    hosts_apply || return 1
    dnsmasq_clear
  elif [ "$method" = dnsmasq ]; then
    hosts_clear
    if ! dnsmasq_apply; then
      say_warn "dnsmasq 没接好，改写入 /etc/hosts。"
      printf '%s\n' hosts >"$CFG/dns.method"
      hosts_apply || return 1
    fi
  else
    hosts_clear
    dnsmasq_clear
  fi
  return 0
}

#----------------------------------------------------------------------
# 域名：整机封禁才拦解析。按端口封时只封解析到的 IP。
#----------------------------------------------------------------------

hosts_clear() {
  [ -f /etc/hosts ] || return 0
  if ! grep -q '# BEGIN vps-fengjin' /etc/hosts 2>/dev/null; then
    return 0
  fi
  awk '
    $0 == "# BEGIN vps-fengjin" { s = 1; next }
    $0 == "# END vps-fengjin" { s = 0; next }
    s != 1 { print }
  ' /etc/hosts >"$WORKDIR/hosts.new"
  cat "$WORKDIR/hosts.new" >/etc/hosts
}

hosts_apply() {
  [ -s "$CFG/dns.list" ] || return 0
  hosts_clear
  n=$(wc -l <"$CFG/dns.list" | awk '{ print $1 }')
  src=$CFG/dns.list
  if [ "${n:-0}" -gt 2000 ]; then
    say_warn "/etc/hosts 只写入前 2000 个域名，太多会拖慢这台机器。"
    head -n 2000 "$CFG/dns.list" >"$WORKDIR/hosts.names"
    src=$WORKDIR/hosts.names
  fi
  {
    cat /etc/hosts 2>/dev/null || true
    printf '%s\n' "# BEGIN vps-fengjin"
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      printf '0.0.0.0 %s\n' "$name"
      printf ':: %s\n' "$name"
    done <"$src"
    printf '%s\n' "# END vps-fengjin"
  } >"$WORKDIR/hosts.full"
  cat "$WORKDIR/hosts.full" >/etc/hosts
}

# 两种情况：
#   本来就在跑的 dnsmasq（OpenWrt 路由、别的程序装的）：只追加拦截的域名，
#     不碰它的监听地址和上游，否则会把局域网的 DNS 弄坏。
#   脚本自己装、自己拉起来的：记在 dnsmasq.owned，只听 127.0.0.1。
#     关闭时连服务一起停掉，免得重启后按默认配置对外开放 53 端口。
dnsmasq_clear() {
  changed=0
  if [ -f /etc/dnsmasq.d/vps-fengjin.conf ]; then
    rm -f /etc/dnsmasq.d/vps-fengjin.conf
    changed=1
  fi
  if [ -f /etc/dnsmasq.conf ] && grep -q '# BEGIN vps-fengjin' /etc/dnsmasq.conf 2>/dev/null; then
    awk '
      $0 == "# BEGIN vps-fengjin" { s = 1; next }
      $0 == "# END vps-fengjin" { s = 0; next }
      s != 1 { print }
    ' /etc/dnsmasq.conf >"$WORKDIR/dnsmasq.conf.new"
    cat "$WORKDIR/dnsmasq.conf.new" >/etc/dnsmasq.conf
    changed=1
  fi
  if [ -f /etc/resolv.conf ] && grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null; then
    if [ -f "$CFG/resolv.conf.bak" ]; then
      cat "$CFG/resolv.conf.bak" >/etc/resolv.conf
    fi
  fi
  if [ -f "$CFG/dnsmasq.owned" ]; then
    stop_dnsmasq
    rm -f "$CFG/dnsmasq.owned"
  elif [ "$changed" = 1 ] && pidof dnsmasq >/dev/null 2>&1; then
    restart_dnsmasq || true
  fi
}

write_dnsmasq_conf() {
  dest=$1
  full=$2
  {
    if [ "$full" = 1 ]; then
      printf '%s\n' "listen-address=127.0.0.1"
      printf '%s\n' "bind-interfaces"
      printf '%s\n' "no-resolv"
      printf '%s\n' "no-hosts"
      printf '%s\n' "cache-size=50"
      printf '%s\n' "domain-needed"
      if [ -s "$CFG/upstream.dns" ]; then
        awk 'NF { print "server=" $1 }' "$CFG/upstream.dns"
      else
        printf '%s\n' "server=1.1.1.1"
        printf '%s\n' "server=8.8.8.8"
      fi
    fi
    # 名单可能有几十万行，用 awk 写，shell 逐行太慢。
    # 不写地址的 address=/域名/ 对 IPv4、IPv6 都回“不存在”，子域名一起拦。
    # 一个域名一行，比分别写 0.0.0.0 和 :: 省一半内存。
    awk 'NF { print "address=/" $1 "/" }' "$CFG/dns.list"
  } >"$dest"
}

# dnsmasq.conf 里有没有真正生效的 conf-dir（不算注释掉的那行）。
# Debian 系的启动脚本自己会带上 /etc/dnsmasq.d。
dnsmasq_reads_confdir() {
  [ -f /etc/default/dnsmasq ] && grep -q '^CONFIG_DIR=/etc/dnsmasq.d' /etc/default/dnsmasq 2>/dev/null && return 0
  [ -f /etc/dnsmasq.conf ] && grep -E -q '^[[:space:]]*conf-dir=/etc/dnsmasq\.d' /etc/dnsmasq.conf 2>/dev/null && return 0
  return 1
}

restart_dnsmasq() {
  if [ -x /etc/init.d/dnsmasq ]; then
    /etc/init.d/dnsmasq restart >/dev/null 2>&1 && return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl enable dnsmasq >/dev/null 2>&1 || true
    systemctl restart dnsmasq >/dev/null 2>&1 && return 0
  fi
  if command -v rc-service >/dev/null 2>&1; then
    rc-service dnsmasq restart >/dev/null 2>&1 && return 0
  fi
  killall dnsmasq 2>/dev/null || true
  if command -v dnsmasq >/dev/null 2>&1; then
    dnsmasq && return 0
  fi
  return 1
}

stop_dnsmasq() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now dnsmasq >/dev/null 2>&1 || true
  fi
  if command -v rc-service >/dev/null 2>&1; then
    rc-service dnsmasq stop >/dev/null 2>&1 || true
    rc-update del dnsmasq default >/dev/null 2>&1 || true
  fi
  if [ -x /etc/init.d/dnsmasq ]; then
    /etc/init.d/dnsmasq stop >/dev/null 2>&1 || true
  fi
  killall dnsmasq 2>/dev/null || true
}

dns_query_at() {
  name=$1
  srv=$2
  if command -v dig >/dev/null 2>&1; then
    dig +time=2 +tries=1 +short "$name" "@$srv"
    return 0
  fi
  if command -v host >/dev/null 2>&1; then
    host "$name" "$srv"
    return 0
  fi
  if command -v nslookup >/dev/null 2>&1; then
    nslookup "$name" "$srv"
    return 0
  fi
  return 1
}

dnsmasq_apply() {
  [ -s "$CFG/dns.list" ] || return 0
  shared=0
  if [ ! -f "$CFG/dnsmasq.owned" ] && { [ "$OS_ID" = openwrt ] || pidof dnsmasq >/dev/null 2>&1; }; then
    shared=1
  fi
  if [ "$shared" = 0 ]; then
    # resolv.conf 是链接时归 systemd-resolved 之类管，本机不会来问这个 dnsmasq，拦了等于没拦。
    [ -L /etc/resolv.conf ] && return 1
    if ! command -v dig >/dev/null 2>&1 && ! command -v host >/dev/null 2>&1 && ! command -v nslookup >/dev/null 2>&1; then
      return 1
    fi
  fi
  mkdir -p /etc/dnsmasq.d 2>/dev/null || true
  if [ -d /etc/dnsmasq.d ]; then
    # 先写好配置再装，Debian 装完会马上启动，这样一开始就只听 127.0.0.1。
    write_dnsmasq_conf /etc/dnsmasq.d/vps-fengjin.conf "$((1 - shared))"
  fi
  if ! command -v dnsmasq >/dev/null 2>&1; then
    if ! pm_install dnsmasq; then
      dnsmasq_clear
      return 1
    fi
  fi
  if [ -d /etc/dnsmasq.d ]; then
    if ! dnsmasq_reads_confdir; then
      printf '\n%s\n' "conf-dir=/etc/dnsmasq.d/,*.conf" >>/etc/dnsmasq.conf
    fi
  else
    {
      printf '%s\n' "# BEGIN vps-fengjin"
      write_dnsmasq_conf "$WORKDIR/dnsmasq.body" "$((1 - shared))"
      cat "$WORKDIR/dnsmasq.body"
      printf '%s\n' "# END vps-fengjin"
    } >>/etc/dnsmasq.conf
  fi
  if [ "$shared" = 1 ]; then
    if ! restart_dnsmasq; then
      dnsmasq_clear
      return 1
    fi
    return 0
  fi
  if [ ! -f "$CFG/resolv.conf.bak" ] && [ -f /etc/resolv.conf ]; then
    cp /etc/resolv.conf "$CFG/resolv.conf.bak" || return 1
  fi
  printf '%s\n' 1 >"$CFG/dnsmasq.owned"
  if ! restart_dnsmasq; then
    dnsmasq_clear
    return 1
  fi
  if ! dns_query_at iana.org 127.0.0.1 | head -n 20 | grep -E -q '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|:[0-9A-Fa-f]'; then
    dnsmasq_clear
    return 1
  fi
  printf '%s\n' "# vps-fengjin managed" "nameserver 127.0.0.1" >/etc/resolv.conf
  return 0
}

save_upstreams() {
  if [ -f /etc/resolv.conf ] && grep -q 'vps-fengjin managed' /etc/resolv.conf 2>/dev/null; then
    [ -s "$CFG/upstream.dns" ] && return 0
  fi
  awk '/^nameserver[ \t]+/ { print $2 }' /etc/resolv.conf 2>/dev/null \
    | awk '$1 !~ /^127\./ && $1 != "::1" { print }' >"$CFG/upstream.dns" || true
  # systemd-resolved 的 resolv.conf 只写 127.0.0.53，真正的上游在这里。
  if [ ! -s "$CFG/upstream.dns" ] && [ -r /run/systemd/resolve/resolv.conf ]; then
    awk '/^nameserver[ \t]+/ { print $2 }' /run/systemd/resolve/resolv.conf 2>/dev/null \
      | awk '$1 !~ /^127\./ && $1 != "::1" { print }' >"$CFG/upstream.dns" || true
  fi
  if [ ! -s "$CFG/upstream.dns" ]; then
    printf '%s\n' "1.1.1.1" "8.8.8.8" >"$CFG/upstream.dns"
  fi
}

have_resolver() {
  command -v dig >/dev/null 2>&1 && return 0
  command -v host >/dev/null 2>&1 && return 0
  command -v nslookup >/dev/null 2>&1 && return 0
  command -v getent >/dev/null 2>&1 && return 0
  return 1
}

ensure_resolver() {
  have_resolver && return 0
  say_info "没有查 DNS 的命令，尝试装一个小的。"
  need_cmd host bind9-host bind-utils bind-tools || need_cmd nslookup bind-utils bind-tools || true
  have_resolver
}

run_timeout() {
  secs=$1
  out=$2
  shift 2
  if command -v timeout >/dev/null 2>&1 && timeout 1 true >/dev/null 2>&1; then
    timeout "$secs" "$@" >"$out" 2>/dev/null
    return $?
  fi
  "$@" >"$out" 2>/dev/null &
  pid=$!
  i=0
  while [ "$i" -lt "$secs" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      return $?
    fi
    sleep 1
    i=$((i + 1))
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

resolve_one() {
  name=$1
  srv=$2
  out=$3
  : >"$out"
  # dig 和 host 自带超时，直接跑，不用每个名字都等上一秒。
  # dig 默认只查 A 记录，要另外查 AAAA，不然 IPv6 地址漏封。
  if command -v dig >/dev/null 2>&1; then
    dig "@$srv" +time=2 +tries=1 +short "$name" A "$name" AAAA >"$out" 2>/dev/null || true
    return 0
  fi
  if command -v host >/dev/null 2>&1; then
    host -W 2 "$name" "$srv" >"$out" 2>/dev/null || true
    return 0
  fi
  if command -v nslookup >/dev/null 2>&1; then
    run_timeout 5 "$out" nslookup "$name" "$srv" || true
    return 0
  fi
  if command -v getent >/dev/null 2>&1; then
    run_timeout 4 "$out" getent hosts "$name" || true
  fi
}

first_upstream() {
  if [ -s "$CFG/upstream.dns" ]; then
    awk 'NF { print; exit }' "$CFG/upstream.dns"
    return 0
  fi
  printf '%s\n' "1.1.1.1"
}

choose_dns_method() {
  count=$1
  mode=$2
  if [ "$mode" != all ] || [ "$count" -eq 0 ]; then
    printf '%s\n' none
    return 0
  fi
  if [ "$OS_ID" = openwrt ]; then
    printf '%s\n' dnsmasq
    return 0
  fi
  if [ "$count" -le 400 ] && [ "$HAVE_STRING" = 1 ] && [ "$FW_BACKEND" = iptables ]; then
    printf '%s\n' string
    return 0
  fi
  if [ "$count" -le 400 ]; then
    printf '%s\n' hosts
    return 0
  fi
  if command -v dnsmasq >/dev/null 2>&1 || [ "${PM:-none}" != none ]; then
    printf '%s\n' dnsmasq
    return 0
  fi
  printf '%s\n' hosts
}

rebuild_ips() {
  mode=$(cat "$CFG/mode")
  excludes=$WORKDIR/exclude.txt
  collect_excludes "$excludes"
  : >"$WORKDIR/v4.raw"
  : >"$WORKDIR/v6.raw"
  : >"$WORKDIR/names.txt"
  # 最多只解析 2000 个名字。写的时候就截住，免得几十万行先排一遍序，小鸡内存吃不消。
  awk -F '\t' -v cap=2000 -v w="$WORKDIR" '
    function name(s) {
      if (c >= cap) { more++; return }
      if (s in seen) return
      seen[s] = 1
      c++
      print s >> (w "/names.txt")
    }
    $1 == "ip4" || $1 == "net4" { print $2 >> (w "/v4.raw") }
    $1 == "ip6" || $1 == "net6" { print $2 >> (w "/v6.raw") }
    $1 == "domain" { name($2) }
    $1 == "suffix" {
      name($2)
      if ($2 !~ /^www\./) name("www." $2)
    }
    END { print c + more > (w "/names.count") }
  ' "$CFG/list.txt"
  if [ -s "$WORKDIR/names.txt" ]; then
    LC_ALL=C sort -u "$WORKDIR/names.txt" -o "$WORKDIR/names.txt"
  fi
  # 整机封禁的 DNS 名单不含自动加的 www，避免把用户没写的名字写进 hosts。
  awk -F '\t' '$1 == "domain" || $1 == "suffix" { print $2 }' "$CFG/list.txt" \
    | LC_ALL=C sort -u >"$CFG/dns.list"
  nnames=$(wc -l <"$CFG/dns.list" | awk '{ print $1 }')
  [ -n "$nnames" ] || nnames=0
  method=$(choose_dns_method "$nnames" "$mode")
  # 按端口封时，后缀只能解析主名字和 www。
  if [ "$mode" != all ] && [ -s "$WORKDIR/names.txt" ]; then
    say_info "按端口封时，只会封这些域名现在解析到的 IP。新冒出来的子域名要等下次刷新。"
  fi
  if [ "$nnames" -gt 0 ]; then
    ensure_resolver || say_warn "没有 DNS 查询命令，域名暂时变不成 IP。"
  fi
  srv=$(first_upstream)
  : >"$WORKDIR/resolved.txt"
  total=$(wc -l <"$WORKDIR/names.txt" | awk '{ print $1 }')
  [ -n "$total" ] || total=0
  if [ "$(cat "$WORKDIR/names.count" 2>/dev/null || echo 0)" -gt 2000 ]; then
    say_warn "域名超过 2000 个，只解析前 2000 个的 IP。"
  fi
  n=0
  failn=0
  if [ "$total" -gt 0 ] && have_resolver; then
    say_step "正在把域名解析成 IP"
    pause_dns_rules
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      n=$((n + 1))
      if [ $((n % 20)) -eq 0 ]; then
        say_info "已解析 $n / $total"
      fi
      resolve_one "$name" "$srv" "$WORKDIR/one.txt"
      got=$(fengjin_awk extract "" "$srv" <"$WORKDIR/one.txt" || true)
      if [ -z "$got" ]; then
        failn=$((failn + 1))
      else
        printf '%s\n' "$got" >>"$WORKDIR/resolved.txt"
      fi
    done <"$WORKDIR/names.txt"
  fi
  # 一个都没解析出来，多半是网络临时断了。沿用上次的结果，别让定时刷新把域名的 IP 全放开。
  if [ -s "$WORKDIR/resolved.txt" ]; then
    cp "$WORKDIR/resolved.txt" "$CFG/resolved.last"
  elif [ "$total" -gt 0 ] && [ -s "$CFG/resolved.last" ]; then
    say_warn "这次一个域名都没解析到，沿用上次解析到的 IP。"
    cp "$CFG/resolved.last" "$WORKDIR/resolved.txt"
  fi
  if [ -s "$WORKDIR/resolved.txt" ]; then
    while IFS= read -r ip; do
      case $ip in
        *:*) printf '%s\n' "$ip" >>"$WORKDIR/v6.raw" ;;
        *) printf '%s\n' "$ip" >>"$WORKDIR/v4.raw" ;;
      esac
    done <"$WORKDIR/resolved.txt"
  fi
  filter_family 4 "$WORKDIR/v4.raw" "$CFG/v4" "$excludes"
  filter_family 6 "$WORKDIR/v6.raw" "$CFG/v6" "$excludes"
  cat "$WORKDIR/skip.4" "$WORKDIR/skip.6" 2>/dev/null >"$WORKDIR/skipped.txt" || true
  if [ "$method" = string ] && [ "$nnames" -gt 400 ]; then
    head -n 400 "$CFG/dns.list" >"$WORKDIR/dns.cap"
    cat "$WORKDIR/dns.cap" >"$CFG/dns.list"
    say_warn "按域名拦 DNS 一次最多 400 个，多出来的只封已经解析到的 IP。"
    nnames=400
  fi
  printf '%s\n' "$method" >"$CFG/dns.method"
  if [ "$failn" -gt 0 ] && [ "$mode" != all ]; then
    say_warn "$failn 个域名没解析到。按端口封时，这些名字拦不住。"
  fi
  if [ -s "$WORKDIR/skipped.txt" ]; then
    say_warn "下面这些地址包含你的 SSH 或本机地址，已跳过，避免把自己锁在外面："
    head -n 8 "$WORKDIR/skipped.txt" | while IFS= read -r line; do
      printf '  %s\n' "$line"
    done
  fi
}

filter_family() {
  fam=$1
  src=$2
  dest=$3
  excludes=$4
  skip=$WORKDIR/skip.$fam
  : >"$skip"
  if [ ! -s "$src" ]; then
    : >"$dest"
    return 0
  fi
  LC_ALL=C sort -u "$src" -o "$src"
  awk -v fam="$fam" '
    index($0, "/") > 0 { print "net" fam "\t" $0; next }
    { print "ip" fam "\t" $0 }
  ' "$src" | fengjin_awk overlap "$excludes" "" "$skip" \
    | awk -F '\t' 'NF >= 2 { print $2 }' >"$dest"
}

#----------------------------------------------------------------------
# 开机继续生效
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
  dest=$BIN_DEFAULT
  mkdir -p /usr/local/sbin 2>/dev/null || dest=/usr/sbin/vps-fengjin
  src=$0
  case $src in
    /*) ;;
    *) src=$(pwd)/$src ;;
  esac
  if [ "$src" != "$dest" ] && [ -f "$src" ]; then
    cp "$src" "$dest"
    chmod 755 "$dest"
  fi
}

write_systemd() {
  bin=$1
  mkdir -p /etc/systemd/system
  cat >"/etc/systemd/system/vps-fengjin.service" <<EOF
[Unit]
Description=Apply saved outbound block list
After=network.target

[Service]
Type=oneshot
ExecStart=$bin apply-rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  cat >"/etc/systemd/system/vps-fengjin-refresh.service" <<EOF
[Unit]
Description=Refresh outbound block list addresses

[Service]
Type=oneshot
ExecStart=$bin refresh
EOF
  cat >"/etc/systemd/system/vps-fengjin-refresh.timer" <<EOF
[Unit]
Description=Refresh outbound block list every 6 hours

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable vps-fengjin.service >/dev/null 2>&1 || true
}

write_openrc() {
  bin=$1
  cat >"/etc/init.d/vps-fengjin" <<EOF
#!/sbin/openrc-run
name="vps-fengjin"
description="Apply saved outbound block list"
depend() { after net firewall; }
start() { $bin apply-rules; }
EOF
  chmod 755 /etc/init.d/vps-fengjin
  rc-update add vps-fengjin default >/dev/null 2>&1 || true
}

write_openwrt_init() {
  bin=$1
  cat >"/etc/init.d/vps-fengjin" <<EOF
#!/bin/sh /etc/rc.common
START=95
start() { $bin apply-rules; }
EOF
  chmod 755 /etc/init.d/vps-fengjin
  /etc/init.d/vps-fengjin enable >/dev/null 2>&1 || true
}

strip_marked_file() {
  file=$1
  [ -f "$file" ] || return 0
  if ! grep -q '# BEGIN vps-fengjin' "$file" 2>/dev/null; then
    return 0
  fi
  awk '
    $0 == "# BEGIN vps-fengjin" { s = 1; next }
    $0 == "# END vps-fengjin" { s = 0; next }
    s != 1 { print }
  ' "$file" >"$WORKDIR/marked.new"
  cat "$WORKDIR/marked.new" >"$file"
}

append_marked() {
  file=$1
  line=$2
  touch "$file"
  strip_marked_file "$file"
  {
    printf '%s\n' "# BEGIN vps-fengjin"
    printf '%s\n' "$line"
    printf '%s\n' "# END vps-fengjin"
  } >>"$file"
}

install_persistence() {
  bin=$(installed_bin)
  names=$(wc -l <"$CFG/dns.list" 2>/dev/null | awk '{ print $1 }')
  [ -n "$names" ] || names=0
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    write_systemd "$bin"
    if [ "$names" -gt 0 ]; then
      systemctl enable --now vps-fengjin-refresh.timer >/dev/null 2>&1 || true
    else
      systemctl disable --now vps-fengjin-refresh.timer >/dev/null 2>&1 || true
    fi
    return 0
  fi
  if [ -f /etc/openwrt_release ]; then
    write_openwrt_init "$bin"
    if [ -f /etc/firewall.user ] || [ -d /etc ]; then
      touch /etc/firewall.user
      append_marked /etc/firewall.user "$bin apply-rules"
    fi
  elif command -v rc-update >/dev/null 2>&1 && [ -d /etc/init.d ]; then
    write_openrc "$bin"
  elif [ -f /etc/rc.local ]; then
    append_marked /etc/rc.local "$bin apply-rules"
  else
    say_warn "没找到开机自启的位置。重启后请再运行一次：vps-fengjin apply-rules"
  fi
  if [ "$names" -gt 0 ]; then
    if [ -d /etc/cron.d ]; then
      cat >"/etc/cron.d/vps-fengjin" <<EOF
17 */6 * * * root $bin refresh
EOF
    elif [ -f /etc/crontabs/root ] || [ -d /etc/crontabs ]; then
      mkdir -p /etc/crontabs
      if [ -f /etc/crontabs/root ]; then
        grep -v 'vps-fengjin refresh' /etc/crontabs/root >"$WORKDIR/cron.root" || true
        cat "$WORKDIR/cron.root" >"/etc/crontabs/root"
      fi
      printf '%s\n' "17 */6 * * * $bin refresh" >>/etc/crontabs/root
    fi
  fi
}

remove_persistence() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now vps-fengjin.service >/dev/null 2>&1 || true
    systemctl disable --now vps-fengjin-refresh.timer >/dev/null 2>&1 || true
  fi
  rm -f /etc/systemd/system/vps-fengjin.service \
    /etc/systemd/system/vps-fengjin-refresh.service \
    /etc/systemd/system/vps-fengjin-refresh.timer
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if command -v rc-update >/dev/null 2>&1; then
    rc-update del vps-fengjin default >/dev/null 2>&1 || true
  fi
  # OpenWrt 要先 disable，不然 /etc/rc.d 里留下指向空文件的链接。
  if [ -f /etc/openwrt_release ] && [ -x /etc/init.d/vps-fengjin ]; then
    /etc/init.d/vps-fengjin disable >/dev/null 2>&1 || true
  fi
  rm -f /etc/init.d/vps-fengjin /etc/cron.d/vps-fengjin
  if [ -f /etc/crontabs/root ]; then
    grep -v 'vps-fengjin refresh' /etc/crontabs/root >"$WORKDIR/cron.root" || true
    cat "$WORKDIR/cron.root" >/etc/crontabs/root
  fi
  strip_marked_file /etc/firewall.user
  strip_marked_file /etc/rc.local
}

#----------------------------------------------------------------------
# 问答
#----------------------------------------------------------------------

ask_line() {
  prompt=$1
  ans=
  if [ -r /dev/tty ]; then
    printf '%s' "$prompt" >/dev/tty
    IFS= read -r ans </dev/tty || return 1
  else
    printf '%s' "$prompt"
    IFS= read -r ans || return 1
  fi
  printf '%s\n' "$ans" | sed 's/^[ \t]*//;s/[ \t]*$//'
}

tty_say() {
  if [ -w /dev/tty ]; then
    printf '%s\n' "$1" >/dev/tty
  else
    printf '%s\n' "$1"
  fi
}

paste_into() {
  dest=$1
  tty_say "请粘贴名单，一行一个。粘贴完后，另起一行只输入 END 再回车。"
  n=0
  while :; do
    if [ -r /dev/tty ]; then
      IFS= read -r line </dev/tty || break
    else
      IFS= read -r line || break
    fi
    # 从 Windows 终端粘贴时行尾会带 \r 或空格。
    case $line in
      END|end|END[[:space:]]*|end[[:space:]]*) break ;;
    esac
    printf '%s\n' "$line" >>"$dest"
    n=$((n + 1))
    if [ "$n" -ge 20000 ]; then
      say_warn "已经收了 20000 行，后面的不再收。"
      break
    fi
  done
  say_ok "这次收到 $n 行"
}

file_into() {
  dest=$1
  if ! path=$(ask_line "文件路径："); then
    return 1
  fi
  path=$(printf '%s' "$path" | sed 's/^"//;s/"$//;s/^'"'"'//;s/'"'"'$//')
  if [ ! -f "$path" ]; then
    say_err "找不到这个文件。"
    return 1
  fi
  size=$(wc -c <"$path" | awk '{ print $1 }')
  list_limits
  if [ "$size" -gt "$LIST_MAX_BYTES" ]; then
    say_err "文件超过 ${LIST_MAX_MB}MB，这台机器的内存吃不消。"
    return 1
  fi
  cat "$path" >>"$dest"
  say_ok "已读入文件"
}

fetch_url() {
  url=$1
  out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 60 -o "$out" "$url" && return 0
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -T 60 -O "$out" "$url" && return 0
  fi
  return 1
}

url_into() {
  dest=$1
  if ! url=$(ask_line "名单网址："); then
    return 1
  fi
  case $url in
    http://*|https://*) ;;
    *) say_err "只接受 http 或 https 网址。"; return 1 ;;
  esac
  if ! fetch_url "$url" "$WORKDIR/download.txt"; then
    say_err "下载失败。"
    return 1
  fi
  size=$(wc -c <"$WORKDIR/download.txt" | awk '{ print $1 }')
  list_limits
  if [ "$size" -gt "$LIST_MAX_BYTES" ]; then
    say_err "下载内容超过 ${LIST_MAX_MB}MB，这台机器的内存吃不消。"
    rm -f "$WORKDIR/download.txt"
    return 1
  fi
  sig=$(dd if="$WORKDIR/download.txt" bs=80 count=1 2>/dev/null | tr 'A-Z' 'a-z')
  case $sig in
    *'<html'*|*'<!doctype'*)
      say_err "下载到的是网页，不是名单。"
      return 1
      ;;
  esac
  cat "$WORKDIR/download.txt" >>"$dest"
  say_ok "网址里的名单已读入"
}

bad_reason() {
  case $1 in
    wide) printf '%s\n' "网段太大，怕把整台机器封死" ;;
    local) printf '%s\n' "这是本机或广播地址" ;;
    keyword) printf '%s\n' "关键词太宽" ;;
    unsupported) printf '%s\n' "这种规则类型不支持" ;;
    *) printf '%s\n' "看不懂" ;;
  esac
}

summarize_list() {
  src=$1
  N_DOMAIN=0
  N_SUFFIX=0
  N_IP=0
  N_BAD=0
  N_DOMAIN=$(awk -F '\t' '$1 == "domain" { c++ } END { print c + 0 }' "$src")
  N_SUFFIX=$(awk -F '\t' '$1 == "suffix" { c++ } END { print c + 0 }' "$src")
  N_IP=$(awk -F '\t' '$1 == "ip4" || $1 == "net4" || $1 == "ip6" || $1 == "net6" { c++ } END { print c + 0 }' "$src")
  N_BAD=$(awk -F '\t' '$1 == "bad" { c++ } END { print c + 0 }' "$src")
}

show_bads() {
  src=$1
  [ "$N_BAD" -gt 0 ] || return 0
  say_warn "有 $N_BAD 行没用上，最多显示 8 行："
  awk -F '\t' '$1 == "bad" { print $2 "\t" $3 }' "$src" | head -n 8 | while IFS= read -r line; do
    code=${line%%	*}
    rest=${line#*	}
    why=$(bad_reason "$code")
    printf '  %s：%s\n' "$why" "$rest"
  done
}

classify_raw() {
  raw=$1
  out=$2
  fengjin_awk classify <"$raw" >"$WORKDIR/class.all"
  # 先截掉超出上限的域名再排序。sort 要把整份读进内存，
  # 30 万行要 30MB，64MB 小鸡受不了；截到 10 万行只要三分之一。
  list_limits
  : >"$WORKDIR/class.bad"
  : >"$WORKDIR/class.ips"
  : >"$WORKDIR/class.names"
  awk -F '\t' -v cap="$LIST_MAX_ITEMS" -v w="$WORKDIR" '
    $1 == "bad" { print > (w "/class.bad"); next }
    $1 == "domain" || $1 == "suffix" {
      n++
      if (n <= cap) print > (w "/class.names")
      next
    }
    { print > (w "/class.ips") }
    END { print n + 0 > (w "/class.nnames") }
  ' "$WORKDIR/class.all"
  nn=$(cat "$WORKDIR/class.nnames" 2>/dev/null || echo 0)
  if [ "$nn" -gt "$LIST_MAX_ITEMS" ]; then
    say_warn "名单里有 $nn 个域名，这台机器最多用 $LIST_MAX_ITEMS 个，后面的不用。"
  fi
  cat "$WORKDIR/class.ips" "$WORKDIR/class.names" | LC_ALL=C sort -u >"$out"
}

cap_list() {
  list=$1
  list_limits
  # 上限只算域名，吃内存的是 dnsmasq 里的域名。IP 进 ipset，全部保留。
  n=$(awk -F '\t' '$1 == "domain" || $1 == "suffix" { c++ } END { print c + 0 }' "$list")
  if [ "${n:-0}" -gt "$LIST_MAX_ITEMS" ]; then
    say_warn "域名超过 $LIST_MAX_ITEMS 个，这台机器只保留前 $LIST_MAX_ITEMS 个。"
    awk -F '\t' -v cap="$LIST_MAX_ITEMS" '
      $1 == "domain" || $1 == "suffix" { if (++c > cap) next }
      { print }
    ' "$list" >"$WORKDIR/list.cap"
    cat "$WORKDIR/list.cap" >"$list"
  fi
}

collect_sources() {
  dest=$1
  : >"$dest"
  while :; do
    tty_say ""
    tty_say "名单怎么添加？"
    tty_say "  1) 粘贴。一行一个，最后一行输入 END"
    tty_say "  2) 这台机器上已经有的文件"
    tty_say "  3) 名单网址"
    tty_say "  0) 添加完了，下一步"
    if ! choice=$(ask_line "请选择 [0]: "); then
      die "读不到键盘输入。"
    fi
    [ -n "$choice" ] || choice=0
    case $choice in
      1) paste_into "$dest" || true ;;
      2) file_into "$dest" || true ;;
      3) url_into "$dest" || true ;;
      0)
        if [ ! -s "$dest" ]; then
          say_warn "还没有名单。"
          continue
        fi
        return 0
        ;;
      *) say_warn "请输入 1、2、3 或 0。" ;;
    esac
  done
}

ask_scope() {
  while :; do
    tty_say ""
    tty_say "封在什么范围？这里的端口是对方网站的端口，不是这台机器对外开的端口。"
    tty_say "  1) 只封一个目标端口。例如只拦 443，别的端口还能连这些地址"
    tty_say "  2) 封多个目标端口。例如 80 和 443"
    tty_say "  3) 整台机器。不管哪个端口，都不让访问名单里的地址"
    if ! choice=$(ask_line "请选择 [3]: "); then
      die "读不到键盘输入。"
    fi
    [ -n "$choice" ] || choice=3
    case $choice in
      1)
        while :; do
          if ! raw=$(ask_line "输入一个目标端口（1 到 65535），例如 443："); then
            die "读不到键盘输入。"
          fi
          ports=$(parse_ports "$raw")
          ec=$?
          if [ "$ec" -eq 0 ]; then
            MODE=ports
            PORTS=$ports
            return 0
          fi
          if [ "$ec" -eq 2 ]; then
            say_err "一次最多 30 个端口。要封更多就选整台机器。"
          else
            say_err "端口不对。请输入 1 到 65535 的数字。"
          fi
        done
        ;;
      2)
        while :; do
          if ! raw=$(ask_line "输入目标端口，用空格或逗号分开，例如 80,443："); then
            die "读不到键盘输入。"
          fi
          ports=$(parse_ports "$raw")
          ec=$?
          if [ "$ec" -eq 0 ]; then
            MODE=ports
            PORTS=$ports
            return 0
          fi
          if [ "$ec" -eq 2 ]; then
            say_err "一次最多 30 个端口。要封更多就选整台机器。"
          else
            say_err "端口不对。例子：80,443"
          fi
        done
        ;;
      3)
        MODE=all
        PORTS=
        return 0
        ;;
      *) say_warn "请输入 1、2 或 3。" ;;
    esac
  done
}

confirm_apply() {
  tty_say ""
  tty_say "即将封禁"
  printf '  域名 %s 个，其中整段后缀 %s 个\n' "$N_DOMAIN" "$N_SUFFIX"
  printf '  IP / 网段 %s 个\n' "$N_IP"
  if [ "$MODE" = all ]; then
    tty_say "  范围：整台机器"
    tty_say "  域名的解析会被拦住，这些域名当前的 IP 也会封掉。"
    tty_say "  好几家网站如果共用同一个 IP，可能误伤别的网站。"
  else
    printf '  范围：只封目标端口 %s\n' "$PORTS"
    tty_say "  域名会先解析成 IP，只在这些端口上封。"
    tty_say "  共用同一个 IP 的别的网站，这些端口也可能连不上。"
  fi
  tty_say "  只拦这台机器自己发出去的连接，包括代理程序替用户连出去的连接。"
  if ! ans=$(ask_line "确认执行请输入 y："); then
    die "读不到键盘输入。"
  fi
  case $ans in
    y|Y|yes|YES|是) return 0 ;;
  esac
  say_info "已取消，什么都没改。"
  exit 0
}

write_status() {
  [ -n "${OS_PRETTY:-}" ] || detect_os
  mode=$(cat "$CFG/mode")
  ports=$(cat "$CFG/ports" 2>/dev/null || true)
  method=$(cat "$CFG/dns.method" 2>/dev/null || echo none)
  en=$(cat "$CFG/enabled" 2>/dev/null || echo 0)
  nd=$(awk -F '\t' '$1 == "domain" { c++ } END { print c + 0 }' "$CFG/list.txt" 2>/dev/null || echo 0)
  ns=$(awk -F '\t' '$1 == "suffix" { c++ } END { print c + 0 }' "$CFG/list.txt" 2>/dev/null || echo 0)
  ni=$(awk -F '\t' '$1 == "ip4" || $1 == "net4" || $1 == "ip6" || $1 == "net6" { c++ } END { print c + 0 }' "$CFG/list.txt" 2>/dev/null || echo 0)
  nv4=$(wc -l <"$CFG/v4" 2>/dev/null | awk '{ print $1 }')
  nv6=$(wc -l <"$CFG/v6" 2>/dev/null | awk '{ print $1 }')
  [ -n "$nv4" ] || nv4=0
  [ -n "$nv6" ] || nv6=0
  {
    if [ "$en" = 1 ]; then
      printf '%s\n' "状态：开着"
    else
      printf '%s\n' "状态：关着"
    fi
    printf '系统：%s\n' "${OS_PRETTY:-未知}"
    if [ "$mode" = all ]; then
      printf '%s\n' "范围：整台机器"
    else
      printf '范围：目标端口 %s\n' "$ports"
    fi
    printf '名单：域名 %s 个，整段后缀 %s 个，IP / 网段 %s 个\n' "$nd" "$ns" "$ni"
    printf '实际封住的地址：IPv4 %s 条，IPv6 %s 条\n' "$nv4" "$nv6"
    case $method in
      string) printf '%s\n' "域名拦截：拦发往 53 端口的域名查询，不改本机 DNS 设置" ;;
      dnsmasq) printf '%s\n' "域名拦截：dnsmasq 把这些域名指到空地址" ;;
      hosts) printf '%s\n' "域名拦截：写入 /etc/hosts。子域名可能拦不住" ;;
      *) printf '%s\n' "域名拦截：没有。只封 IP" ;;
    esac
    printf '版本：%s\n' "$VERSION"
  } >"$CFG/status.txt"
}

cmd_status() {
  if [ ! -f "$CFG/status.txt" ]; then
    say_info "这台机器还没有封禁记录。"
    return 0
  fi
  cat "$CFG/status.txt"
  tty_say ""
  tty_say "关闭：vps-fengjin off"
  tty_say "再打开或改名单：vps-fengjin"
}

cmd_check() {
  file=$1
  [ -n "$file" ] || die "用法：sh install.sh check 名单文件"
  [ -f "$file" ] || die "找不到文件。"
  fengjin_awk classify <"$file" >"$WORKDIR/check.all"
  awk -F '\t' '$1 != "bad"' "$WORKDIR/check.all" | LC_ALL=C sort -u >"$WORKDIR/check.good"
  summarize_list "$WORKDIR/check.all"
  printf '域名 %s 个，整段后缀 %s 个，IP / 网段 %s 个，跳过 %s 行\n' \
    "$N_DOMAIN" "$N_SUFFIX" "$N_IP" "$N_BAD"
  show_bads "$WORKDIR/check.all"
}

activate() {
  mkdir -p "$CFG"
  save_upstreams
  ensure_firewall
  rebuild_ips
  nv4=$(wc -l <"$CFG/v4" 2>/dev/null | awk '{ print $1 }')
  nv6=$(wc -l <"$CFG/v6" 2>/dev/null | awk '{ print $1 }')
  method=$(cat "$CFG/dns.method")
  [ -n "$nv4" ] || nv4=0
  [ -n "$nv6" ] || nv6=0
  if [ "$nv4" -eq 0 ] && [ "$nv6" -eq 0 ] && [ "$method" = none ]; then
    die "没有可以封的地址。按端口封域名时，需要先解析出 IP。"
  fi
  printf '%s\n' 1 >"$CFG/enabled"
  if ! load_rules; then
    printf '%s\n' 0 >"$CFG/enabled"
    remove_firewall
    die "规则没有生效，已撤掉本次修改。"
  fi
  write_status
  install_persistence
  say_ok "已经生效。重启后还会自动封上。"
  cmd_status
}

wizard() {
  raw=$WORKDIR/raw.txt
  collect_sources "$raw"
  classify_raw "$raw" "$WORKDIR/good.txt"
  summarize_list "$WORKDIR/good.txt"
  N_BAD=$(awk -F '\t' '$1 == "bad" { c++ } END { print c + 0 }' "$WORKDIR/class.all")
  show_bads "$WORKDIR/class.all"
  goodn=$((N_DOMAIN + N_SUFFIX + N_IP))
  if [ "$goodn" -eq 0 ]; then
    die "名单里没有能用的域名或 IP。"
  fi
  say_ok "可用：域名 $N_DOMAIN 个，整段后缀 $N_SUFFIX 个，IP / 网段 $N_IP 个"
  cap_list "$WORKDIR/good.txt"
  ask_scope
  confirm_apply
  mkdir -p "$CFG"
  cat "$WORKDIR/good.txt" >"$CFG/list.txt"
  rm -f "$CFG/resolved.last"
  printf '%s\n' "$MODE" >"$CFG/mode"
  printf '%s\n' "$PORTS" >"$CFG/ports"
  activate
}

append_wizard() {
  raw=$WORKDIR/raw.txt
  collect_sources "$raw"
  classify_raw "$raw" "$WORKDIR/good.txt"
  summarize_list "$WORKDIR/class.all"
  show_bads "$WORKDIR/class.all"
  cat "$CFG/list.txt" "$WORKDIR/good.txt" | LC_ALL=C sort -u >"$WORKDIR/merged.txt"
  cap_list "$WORKDIR/merged.txt"
  MODE=$(cat "$CFG/mode")
  PORTS=$(cat "$CFG/ports" 2>/dev/null || true)
  if ! ans=$(ask_line "沿用现在的封禁范围？回车沿用，输入 n 重选："); then
    die "读不到键盘输入。"
  fi
  case $ans in
    n|N) ask_scope ;;
  esac
  summarize_list "$WORKDIR/merged.txt"
  # 确认之后才写回去。取消时名单和范围都保持原样。
  confirm_apply
  cat "$WORKDIR/merged.txt" >"$CFG/list.txt"
  printf '%s\n' "$MODE" >"$CFG/mode"
  printf '%s\n' "$PORTS" >"$CFG/ports"
  say_ok "名单已追加。"
  activate
}

intro() {
  detect_os
  kb=$(mem_total_kb)
  mem_show=未知
  if [ -n "$kb" ]; then
    mem_show="$((kb / 1024)) MB"
  fi
  tty_say "这个脚本让这台服务器访问不了你给出的域名或 IP。"
  tty_say "你现在登录用的来源地址会被自动躲开，避免把自己锁在外面。"
  printf '系统：%s\n' "$OS_PRETTY"
  printf '内存：%s\n' "$mem_show"
  tty_say ""
  tty_say "名单可以混着写，一行一个。支持："
  tty_say "  域名            example.com"
  tty_say "  整段后缀        .example.com 或 *.example.com"
  tty_say "  IP              1.2.3.4"
  tty_say "  网段            1.2.3.0/24"
  tty_say "  常见名单        DOMAIN-SUFFIX,example.com"
  tty_say "                  IP-CIDR,1.2.3.0/24"
  tty_say "                  0.0.0.0 example.com"
  tty_say "                  ||example.com^"
}

menu() {
  while :; do
    tty_say ""
    tty_say "这台机器已经有封禁名单。"
    if [ -f "$CFG/status.txt" ]; then
      cat "$CFG/status.txt"
    fi
    tty_say ""
    tty_say "  1) 用现有名单重新生效"
    tty_say "  2) 换一套新名单"
    tty_say "  3) 追加名单"
    tty_say "  4) 查看状态"
    tty_say "  5) 关闭封禁，名单留着"
    tty_say "  6) 彻底删除"
    tty_say "  0) 退出"
    if ! choice=$(ask_line "请选择 [0]: "); then
      exit 1
    fi
    [ -n "$choice" ] || choice=0
    case $choice in
      1)
        detect_os
        printf '%s\n' 1 >"$CFG/enabled"
        activate
        return 0
        ;;
      2)
        intro
        wizard
        return 0
        ;;
      3)
        append_wizard
        return 0
        ;;
      4) cmd_status ;;
      5)
        printf '%s\n' 0 >"$CFG/enabled"
        remove_firewall
        hosts_clear
        dnsmasq_clear
        write_status
        say_ok "已关闭。名单还在。要再打开，运行 vps-fengjin 选 1。"
        return 0
        ;;
      6)
        if ! ans=$(ask_line "彻底删除请再输入 y："); then
          exit 1
        fi
        case $ans in
          y|Y|yes|YES|是) ;;
          *) say_info "已取消。"; return 0 ;;
        esac
        cmd_purge
        return 0
        ;;
      0) return 0 ;;
      *) say_warn "请输入菜单上的数字。" ;;
    esac
  done
}

require_root() {
  if [ "$(id -u)" != 0 ]; then
    die "请用 root 运行。例如：sudo sh install.sh"
  fi
}

require_linux() {
  if [ "$(uname -s)" != Linux ]; then
    die "请在 Linux 服务器上运行。"
  fi
}

take_lock() {
  LOCKDIR=/tmp/vps-fengjin.lock
  if mkdir "$LOCKDIR" 2>/dev/null; then
    echo $$ >"$LOCKDIR/pid"
    LOCKED=1
    return 0
  fi
  old=$(cat "$LOCKDIR/pid" 2>/dev/null || true)
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
    return 1
  fi
  rm -rf "$LOCKDIR"
  if mkdir "$LOCKDIR" 2>/dev/null; then
    echo $$ >"$LOCKDIR/pid"
    LOCKED=1
    return 0
  fi
  return 1
}

cleanup() {
  if [ -n "${WORKDIR:-}" ] && [ "$WORKDIR" != / ]; then
    rm -rf "$WORKDIR"
  fi
  if [ "${LOCKED:-0}" = 1 ]; then
    rm -rf "${LOCKDIR:-}"
  fi
}

usage() {
  cat <<EOF
用法：
  sh install.sh            按提示设置封禁
  sh install.sh status     查看
  sh install.sh refresh    重新解析域名后再封一次
  sh install.sh off        关闭，名单留着
  sh install.sh purge      彻底删除
  sh install.sh check 文件  只检查名单
EOF
}

cmd_off() {
  mkdir -p "$CFG"
  printf '%s\n' 0 >"$CFG/enabled"
  remove_firewall
  hosts_clear
  dnsmasq_clear
  if [ -f "$CFG/list.txt" ]; then
    detect_os
    write_status
  fi
  say_ok "已关闭。名单还在。"
}

cmd_purge() {
  # dnsmasq_clear 要读 $CFG 里的记录，必须在删目录之前。
  remove_firewall
  hosts_clear
  dnsmasq_clear
  remove_persistence
  if [ -f /swapfile-vps-fengjin ]; then
    swapoff /swapfile-vps-fengjin 2>/dev/null || true
    rm -f /swapfile-vps-fengjin
    if [ -f /etc/fstab ]; then
      grep -v '/swapfile-vps-fengjin' /etc/fstab >"$WORKDIR/fstab.new" || true
      cat "$WORKDIR/fstab.new" >/etc/fstab
    fi
  fi
  rm -rf "$CFG"
  rm -f "$BIN_DEFAULT" /usr/sbin/vps-fengjin
  say_ok "已彻底删除。"
}

cmd_refresh() {
  [ -f "$CFG/list.txt" ] || die "还没有名单。"
  en=$(cat "$CFG/enabled" 2>/dev/null || echo 0)
  if [ "$en" != 1 ]; then
    say_info "封禁是关着的，没有刷新。"
    return 0
  fi
  if ! take_lock; then
    say_warn "另一个封禁任务正在跑。"
    return 0
  fi
  detect_os
  activate
}

cmd_apply_rules() {
  [ -f "$CFG/enabled" ] || exit 0
  if ! take_lock; then
    exit 0
  fi
  detect_os
  load_rules
}

main() {
  umask 022
  WORKDIR=$(mktemp -d "$(pick_tmpdir)/vps-fengjin.XXXXXX" 2>/dev/null || true)
  if [ -z "$WORKDIR" ] || [ ! -d "$WORKDIR" ]; then
    WORKDIR=/tmp/vps-fengjin.$$
    mkdir -p "$WORKDIR" || exit 1
  fi
  LOCKED=0
  trap cleanup EXIT
  case ${1:-} in
    -h|--help|help)
      usage
      exit 0
      ;;
    status)
      cmd_status
      exit 0
      ;;
    check)
      cmd_check "${2:-}"
      exit 0
      ;;
    apply-rules)
      require_linux
      require_root
      cmd_apply_rules
      exit 0
      ;;
    apply|refresh)
      require_linux
      require_root
      cmd_refresh
      exit 0
      ;;
    off)
      require_linux
      require_root
      cmd_off
      exit 0
      ;;
    purge)
      require_linux
      require_root
      if ! take_lock; then
        die "另一个封禁任务正在跑。"
      fi
      # 菜单里的删除要再确认一次。命令行直接删。
      cmd_purge
      exit 0
      ;;
    "")
      ;;
    *)
      usage
      exit 1
      ;;
  esac
  require_linux
  require_root
  if ! take_lock; then
    die "另一个封禁任务正在跑。"
  fi
  install_self
  if [ -f "$CFG/list.txt" ]; then
    menu
  else
    intro
    wizard
  fi
}

if [ "${VPS_FENGJIN_LIB:-}" != 1 ]; then
  main "$@"
fi
