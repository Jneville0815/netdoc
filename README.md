# netdoc

A CLI that diagnoses networking issues for a URL and explains what's actually
happening, one layer at a time.

Point it at a URL and it runs DNS, TCP, and HTTP probes — over both IPv4 and
IPv6 where possible — and prints a structured, colored summary of what
worked, what didn't, and how long each step took.

```
$ netdoc https://example.com

netdoc  https://example.com

  ● dns   ok      A=104.20.23.154,172.66.147.243 AAAA=2606:4700:10::6814:179a,... (53ms)
  ● tcp   warn    ipv4→104.20.23.154:443 in 10ms, ipv6→[2606:4700:10::6814:179a]:443 unreachable (10ms)
  ● http  warn    ipv4 200 HTTP/2.0 in 48ms, ipv6 error: dial tcp6 [2606:4700:10::6814:179a]:443: no route to host (49ms)
```

## Status

Early / actively developed. Working today:

- **DNS** — queries the system resolver plus 1.1.1.1 and 8.8.8.8 directly, for
  both A and AAAA records, and flags discrepancies between resolvers.
- **TCP** — attempts a raw connect over each resolved address family so you
  can tell a DNS problem from a routing/firewall problem.
- **HTTP** — makes the actual request over each address family, capturing
  timing (DNS/connect/TLS/TTFB), the response, and the redirect chain.

Not built yet:

- TLS-specific probing (cert chain, expiry, SNI mismatches) as its own step
- CDN detection
- Local network/environment checks (VPN, proxy, DNS-over-HTTPS interference)
- LLM-powered plain-English synthesis of the results (the whole point of the
  tool — see below)

Everything is userland: no sudo, no ICMP/traceroute, no raw sockets.

## Install

Requires Go 1.26+.

```
go install github.com/Jneville0815/netdoc/cmd/netdoc@latest
```

Or build from a clone:

```
git clone https://github.com/Jneville0815/netdoc.git
cd netdoc
go build -o netdoc ./cmd/netdoc
```

## Usage

```
netdoc [flags] <url>
```

`<url>` accepts a bare hostname, `host:port`, or a full `http(s)://` URL.
Bare hostnames default to `https://`.

| Flag | Default | Description |
|---|---|---|
| `--timeout` | `10` | Per-probe timeout, in seconds |
| `--raw` | `false` | Also print the full JSON probe bundle |

## Why

Most network diagnostic tools dump data and leave you to interpret it. The
goal here is a tool that also teaches: probes are structured well enough
that an LLM pass can walk through the results layer by layer (DNS → TCP →
TLS → HTTP) and explain, in plain English, where a problem actually lives
and what to try next. That synthesis step is planned but not yet wired up —
today's output is the structured summary it will eventually explain.

## License

MIT — see [LICENSE](LICENSE).
