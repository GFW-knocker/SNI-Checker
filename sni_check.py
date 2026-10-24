#!/usr/bin/env python3
"""Interactive SNI checker: send a TLS ClientHello with a chosen SNI to an IP
and report the certificate that comes back, or exactly how it failed.

Input forms (one per prompt):
    example.com                 resolve via DNS, port 443
    example.com@1.2.3.4         send SNI example.com to 1.2.3.4:443
    example.com@1.2.3.4:8443    custom port
    example.com@[2606:4700::1]:443
    example.com@                reuse the previous IP/port
    @1.2.3.4                    no SNI at all
    q / quit / exit / Ctrl-C    leave

The handshake runs over a MemoryBIO on a plain socket, so the raw TCP events
(FIN vs RST vs silence) and any non-TLS bytes (e.g. an injected HTTP block
page) are seen directly instead of being hidden behind ssl's error strings.
"""
import argparse
import hashlib
import ipaddress
import os
import socket
import ssl
import sys
import tempfile
import time

os.system("")  # enables ANSI colours in the Windows console
RED, GRN, YEL, CYN, DIM, RST_ = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[2m", "\033[0m"

WSA_NAMES = {
    10051: "network unreachable",
    10060: "connection timed out",
    10061: "connection refused",
    10065: "host unreachable",
}


def parse_target(line, last):
    """Return (sni, host, port) or raise ValueError."""
    line = line.strip()
    port = 443
    if "@" in line:
        sni, rest = line.split("@", 1)
        if rest == "":
            if not last:
                raise ValueError("no previous IP to reuse")
            return sni, last[0], last[1]
    else:
        sni, rest = line, ""
        # allow "sni:port" without an IP
        if sni.count(":") == 1:
            sni, p = sni.split(":")
            port = int(p)

    host = None
    if rest:
        if rest.startswith("["):  # [v6]:port
            end = rest.index("]")
            host = rest[1:end]
            tail = rest[end + 1:]
            if tail.startswith(":"):
                port = int(tail[1:])
        elif rest.count(":") == 1:  # v4:port or name:port
            host, p = rest.split(":")
            port = int(p)
        else:  # bare v4 / bare v6 / name
            host = rest
    if not sni and not host:
        raise ValueError("need an SNI or an @ip")
    if not host:
        host = sni
    return sni, host, port


def resolve(host, port):
    """Return the address to dial plus every address DNS gave (for display)."""
    try:
        ipaddress.ip_address(host)
        return host, [host]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = []
    for fam, _, _, _, sa in infos:
        if sa[0] not in addrs:
            addrs.append(sa[0])
    v4 = [a for a in addrs if ":" not in a]
    return (v4 or addrs)[0], addrs


def decode_cert(der):
    """Parse DER with the stdlib's own decoder (no third-party deps)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)
    except Exception:
        return None
    finally:
        os.unlink(path)


def name_str(rdns):
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def host_matches(sni, names):
    sni = sni.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == sni:
            return True
        if n.startswith("*.") and "." in sni and sni.split(".", 1)[1] == n[2:]:
            return True
    return False


def show_bytes(data, limit=96):
    chunk = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    more = f" ... (+{len(data) - limit} bytes)" if len(data) > limit else ""
    return f"{chunk.hex(' ')}\n      ascii: {text}{more}"


TLS_ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 22: "record_overflow",
    40: "handshake_failure", 42: "bad_certificate", 47: "illegal_parameter", 48: "unknown_ca",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name", 116: "certificate_required",
    120: "no_application_protocol",
}


def describe_received(data):
    """Explain what the first bytes from the server look like."""
    if not data:
        return "nothing"
    if data[0] == 0x16:
        return "TLS handshake record"
    if data[0] == 0x15 and len(data) >= 7:
        return f"TLS alert: level={data[5]} {TLS_ALERTS.get(data[6], data[6])}"
    if data[:5] in (b"HTTP/", b"<html", b"<HTML", b"<!DOC"):
        return "plain HTTP (block page / non-TLS service?)"
    return "non-TLS bytes"


def probe(sni, ip, port, timeout, alpn):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    # ---- TCP ----
    t0 = time.perf_counter()
    try:
        sock.connect((ip, port))
    except socket.timeout:
        print(f"  {RED}TCP: SYN timeout after {timeout:.1f}s{RST_} - no SYN-ACK (SYN dropped / IP blackholed / host down)")
        return
    except ConnectionRefusedError:
        print(f"  {RED}TCP: RST in reply to SYN{RST_} - port closed or connection refused ({ms(t0)})")
        return
    except OSError as e:
        code = getattr(e, "winerror", None) or e.errno
        print(f"  {RED}TCP: connect failed{RST_} - [{code}] {WSA_NAMES.get(code, e.strerror or e)} ({ms(t0)})")
        return
    t_conn = time.perf_counter() - t0
    print(f"  {GRN}TCP: connected{RST_} in {t_conn * 1000:.0f} ms")

    # ---- TLS over MemoryBIO ----
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    # Python never sends an IP literal as SNI, and None means "no SNI"
    tls = ctx.wrap_bio(inc, out, server_hostname=sni or None)

    received = b""
    t1 = time.perf_counter()
    t_first = None
    try:
        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                pending = out.read()
                if pending:
                    sock.sendall(pending)
                data = sock.recv(65536)
                if not data:
                    tag = "before any reply" if not received else f"after {len(received)} bytes"
                    print(f"  {RED}TLS: FIN from peer {tag}{RST_} ({ms(t1)})")
                    if received:
                        print(f"      got: {describe_received(received)}\n      {show_bytes(received)}")
                    return
                if t_first is None:
                    t_first = time.perf_counter() - t1
                received += data
                inc.write(data)
        pending = out.read()  # client Finished
        if pending:
            sock.sendall(pending)
    except socket.timeout:
        tag = "no reply at all" if not received else f"stalled after {len(received)} bytes"
        print(f"  {RED}TLS: timeout after {timeout:.1f}s - {tag}{RST_} (ClientHello dropped / blackholed?)")
        if received:
            print(f"      got: {describe_received(received)}\n      {show_bytes(received)}")
        return
    except (ConnectionResetError, ConnectionAbortedError) as e:
        tag = "before any reply" if not received else f"after {len(received)} bytes"
        print(f"  {RED}TLS: RST {tag}{RST_} ({ms(t1)}) - {e.__class__.__name__}")
        if received:
            print(f"      got: {describe_received(received)}\n      {show_bytes(received)}")
        return
    except ssl.SSLError as e:
        print(f"  {RED}TLS: error{RST_} ({ms(t1)}) - {e.reason or e}")
        if received:
            print(f"      got: {describe_received(received)}\n      {show_bytes(received)}")
        return
    except OSError as e:
        print(f"  {RED}TLS: socket error{RST_} - {e}")
        return
    finally:
        sock.close()

    ttfb = f", first byte {t_first * 1000:.0f} ms" if t_first is not None else ""
    print(f"  {GRN}TLS: handshake OK{RST_} in {ms(t1)}{ttfb} - "
          f"{tls.version()}, {tls.cipher()[0]}, ALPN={tls.selected_alpn_protocol()}")

    der = tls.getpeercert(binary_form=True)
    if not der:
        print(f"  {YEL}no certificate presented{RST_}")
        return
    print_cert(der, sni)


def print_cert(der, sni):
    info = decode_cert(der) or {}
    sans = [v for k, v in info.get("subjectAltName", ()) if k == "DNS"]
    ip_sans = [v for k, v in info.get("subjectAltName", ()) if k == "IP Address"]
    print(f"  {CYN}Certificate{RST_}")
    if info:
        print(f"    subject : {name_str(info.get('subject', ()))}")
        print(f"    issuer  : {name_str(info.get('issuer', ()))}")
        print(f"    valid   : {info.get('notBefore')}  ->  {info.get('notAfter')}")
        print(f"    serial  : {info.get('serialNumber')}")
        shown = sans[:12]
        extra = f" ... (+{len(sans) - 12} more)" if len(sans) > 12 else ""
        if sans:
            print(f"    SAN     : {', '.join(shown)}{extra}")
        if ip_sans:
            print(f"    IP SAN  : {', '.join(ip_sans)}")
    print(f"    sha256  : {hashlib.sha256(der).hexdigest()}")
    if sni:
        cn = [v for rdn in info.get("subject", ()) for k, v in rdn if k == "commonName"]
        ok = host_matches(sni, sans or cn)
        mark = f"{GRN}yes{RST_}" if ok else f"{RED}NO{RST_}"
        print(f"    matches SNI '{sni}': {mark}  {DIM}(chain trust not checked){RST_}")


def ms(t):
    return f"{(time.perf_counter() - t) * 1000:.0f} ms"


def main():
    ap = argparse.ArgumentParser(description="Interactive SNI / ClientHello checker")
    ap.add_argument("-t", "--timeout", type=float, default=6.0, help="seconds for connect and handshake (default 6)")
    ap.add_argument("--alpn", default="h2,http/1.1", help="comma list, or '' for no ALPN (default h2,http/1.1)")
    ap.add_argument("targets", nargs="*", help="optional targets to run first, same syntax as the prompt")
    args = ap.parse_args()
    alpn = [a for a in args.alpn.split(",") if a]

    print(f"{DIM}format: sni[@ip][:port]   sni@ = reuse last ip   @ip = no SNI   q = quit{RST_}")
    last = None
    queue = list(args.targets)
    while True:
        if queue:
            line = queue.pop(0)
            print(f"sni> {line}")
        else:
            try:
                line = input("sni> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
        if not line:
            continue
        if line.lower() in ("q", "quit", "exit"):
            return
        try:
            sni, host, port = parse_target(line, last)
            ip, all_ips = resolve(host, port)
        except ValueError as e:
            print(f"  {YEL}bad input: {e}{RST_}")
            continue
        except socket.gaierror as e:
            print(f"  {RED}DNS: cannot resolve '{host}'{RST_} - {e}")
            continue
        last = (ip, port)
        dns_note = ""
        if host != ip:
            dns_note = f"  {DIM}(DNS {host} -> {', '.join(all_ips)}){RST_}"
        print(f"  -> {ip}:{port}  SNI={sni or '(none)'}{dns_note}")
        try:
            probe(sni, ip, port, args.timeout, alpn)
        except KeyboardInterrupt:
            print(f"  {YEL}interrupted{RST_}")
        print()


if __name__ == "__main__":
    main()
