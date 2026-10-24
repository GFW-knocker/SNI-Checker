# SNI-Checker
tiny tools to check sni filtering status

Sends a TLS ClientHello with the SNI you choose to an IP, then shows the certificate that comes back. If the handshake fails, it says how: RST, FIN, timeout, TLS alert, or non-TLS bytes such as a block page.

## Usage

Requires Python 3.8+. No extra packages.

```
python sni_check.py
```

Type one target per line at the `sni>` prompt:

| Input | Meaning |
|---|---|
| `x.com` | resolve with DNS, port 443 |
| `x.com@104.16.0.1` | send SNI `x.com` to that IP |
| `x.com@104.16.0.1:8443` | custom port (IPv6: `x.com@[2606:4700::1]:443`) |
| `x.com@` | reuse the previous IP |
| `@1.1.1.1` | send no SNI |
| `q` | quit |

Options:

```
python sni_check.py -t 4                      # timeout in seconds (default 6)
python sni_check.py --alpn ""                 # send no ALPN (default h2,http/1.1)
python sni_check.py x.com@1.1.1.1 google.com@ # run these targets first, then prompt
```
