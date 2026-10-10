# Testing

The module ships a self-contained test suite (`module_test.go`) that
exercises the CNAME-following logic **without any real DNS server**.

## How it works

`module_test.go` starts a tiny authoritative-style fake DNS server on
`127.0.0.1` (UDP for CNAME/SOA lookups, TCP for TSIG-signed dynamic
updates) and points the provider at it. The fake server:

- answers CNAME / SOA queries from a fixed in-memory zone map,
- accepts only TSIG-signed UPDATE messages (rejects a wrong key),
- records every dynamic update it receives so tests can assert which
  **zone** and **record name** the update landed on.

No external network, no BIND, no real zone is touched. Safe to run
anywhere Go runs.

## Fixture zone definitions

The fake server serves a fixed set of records (no real zone files). The
CNAME delegation topology it models:

**CNAME records** (name → target):

| Record (FQDN) | CNAME target | Models |
| --- | --- | --- |
| `_acme-challenge.example.com.` | `challenge.example.net.` | standard ACME DNS-01 CNAME delegation |
| `_acme-challenge.chain.example.com.` | `hop1.example.net.` | multi-hop chain start |
| `hop1.example.net.` | `hop2.example.org.` | second hop (final zone has no SOA) |
| `example.com.` | `acme.example.net.` | domain's own apex CNAME (domain → acme in a delegated zone) |

**SOA zones** (zone → primary master):

| Zone | SOA mname |
| --- | --- |
| `example.com.` | `ns1.example.com.` |
| `example.net.` | `ns1.example.net.` |

Notes:

- `example.org.` (final target of the chain) has **no SOA** → zone lookup
  must fail with a clear error, never write to the wrong zone.
- `acme.example.net.` is the target of `example.com.`'s own apex CNAME;
  tests assert this zone is **never** written to.
- TXT challenge records are synthesized by the tests (`test-validation-string`,
  TTL 120s); they are not part of the fixture map.

## Running the tests

```
go test ./...
```

Verbose (shows each test and the expected-error logs):

```
go test -v ./...
```

Run a single case:

```
go test -v -run TestAppendFollowsCNAME ./...
```

Race detector (recommended for the concurrent fake server):

```
go test -race ./...
```

## What each test covers

| Test | Scenario |
| --- | --- |
| `TestAppendFollowsCNAME` | CNAME at `_acme-challenge.example.com.` → update lands in the delegated zone (`example.net.`) with the record name rewritten to the CNAME target. |
| `TestAppendNoCNAME` | No CNAME at the record name → behavior unchanged, update goes to the original zone. |
| `TestFollowCNAMEDisabled` | `follow_cname false` → restores the old (no-chase) behavior. |
| `TestDeleteFollowsCNAME` | certmagic CleanUp (delete by name+type) removes the TXT at the delegated zone. |
| `TestAppendCNAMEChainZoneLookupFails` | Multi-hop CNAME whose final zone has no SOA → clear error, never writes to the wrong zone. |
| `TestPresentThenCleanupRoundTrip` | Regression for the apex-CNAME case (domain's own CNAME into a delegated zone): the domain's own CNAME target zone is never touched, and the returned record keeps the original relative name so cleanup re-derives the same delegated target. |
| `TestTSIGRejected` | Provider with a wrong TSIG key fails → sanity check that the harness really validates TSIG. |

## Requirements

- Go 1.24+ (matches `go.mod`).
- Loopback networking available (the fake server binds `127.0.0.1`).
- No credentials, no external resolvers — the test supplies its own
  TSIG key and resolver address.
