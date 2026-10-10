# Building & Attribution

This is a **fork of [caddy-dns/rfc2136](https://github.com/caddy-dns/rfc2136)**
that adds **CNAME delegation** support for the ACME DNS-01 challenge.
Original work is © Igor Stuzhuk, MIT License (see [LICENSE](LICENSE)).

## Module name is unchanged

The Caddy module ID is registered as `dns.providers.rfc2136` — identical to
upstream. **Your Caddy config keeps using `rfc2136` as-is**; nothing in the
Caddyfile / JSON changes because of this fork.

Only the Go module path differs: `github.com/ha3730/rfc2136-cname`.

## Build with xcaddy

```
xcaddy build --with github.com/ha3730/rfc2136-cname
```

No `replace` directive is needed: this fork is self-contained at its own
module path, and it registers the same `dns.providers.rfc2136` ID, so the
provider name in your config stays `rfc2136`.

## One provider only

This fork registers the **same** Caddy module name (`dns.providers.rfc2136`)
as upstream. Build with **one** of them, not both — adding both
`caddy-dns/rfc2136` and `ha3730/rfc2136-cname` to the same build collides on
the module ID.

## Config

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

See [README.md](README.md) for the full option reference.
