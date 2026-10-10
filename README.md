RFC2136 DNS provider module for Caddy
===========================

> **Fork of [caddy-dns/rfc2136](https://github.com/caddy-dns/rfc2136)** — adds
> **CNAME delegation** support for the ACME DNS-01 challenge. Original work is
> © Igor Stuzhuk, MIT License (see [LICENSE](LICENSE)). Build instructions are
> in [BUILDING.md](BUILDING.md).

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It can be used to manage DNS records using RFC2136 Dynamic Updates.

## Caddy module name

```
dns.providers.rfc2136
```

## Config examples

To use this module for the ACME DNS challenge, [configure the ACME issuer in your Caddy JSON](https://caddyserver.com/docs/json/apps/tls/automation/policies/issuer/acme/) like so:

```json
{
    "module": "acme",
    "challenges": {
        "dns": {
            "provider": {
                "name": "rfc2136",
                "key": "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4=",
                "key_name": "test",
                "key_alg": "hmac-sha256",
                "server": "1.2.3.4:53"
            }
        }
    }
}
```

or with the Caddyfile:

```
# globally
{
    acme_dns rfc2136 {
        key_name "test"
        key_alg "hmac-sha256"
        key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
        server "1.2.3.4:53"
    }
}
```

```
# one site
tls {
    dns rfc2136 {
        key_name "test"
        key_alg "hmac-sha256"
        key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
        server "1.2.3.4:53"
    }
}
```

## CNAME delegation (DNS-01)

If a CNAME record exists at the record name being written (typically
`_acme-challenge.example.com. CNAME acme.example.net.`), the
dynamic update is performed against the zone of the CNAME's final
target instead of the original zone. This makes the standard ACME
CNAME delegation setup work with RFC2136.

The record operations themselves (dynamic update, TSIG signing) are
still performed by `libdns/rfc2136`; this module only redirects the
target zone/name before delegating.

Options:

- `follow_cname <true|false>` — enable/disable CNAME chasing (default: `true`). Set `false` to restore the old behavior.
- `resolvers <ip...>` — resolvers used for the CNAME and SOA lookups. Defaults to the system resolvers from `/etc/resolv.conf` (same as certmagic's propagation checks).

```
{
    acme_dns rfc2136 {
        key_name "test"
        key_alg "hmac-sha256"
        key "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4="
        server "1.2.3.4:53"
        follow_cname true
        # resolvers "10.0.0.2" "10.0.0.3"
    }
}
```

Note: the delegated target zone must be writable by the same TSIG key
(server). If the final CNAME target's zone cannot be found, the module
returns an error rather than writing to the wrong zone.
