package caddy_dns_rfc2136

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/libdns/rfc2136"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// Provider wraps the libdns RFC2136 provider for use as a Caddy ACME
// DNS-01 challenge provider. All record operations (dynamic update,
// TSIG signing, zone handling) are delegated to libdns/rfc2136; this
// wrapper only adds CNAME chasing: if a CNAME record exists at the
// record name being written (e.g. _acme-challenge.example.com), the
// update is performed against the zone of the CNAME's final target
// instead of the original zone.
type Provider struct {
	*rfc2136.Provider

	// Resolvers used for the CNAME and SOA lookups that determine
	// where a record must actually be written. Defaults to the
	// system resolvers from resolv.conf (same as certmagic's
	// propagation checks).
	Resolvers []string `json:"resolvers,omitempty"`

	// Follow CNAME records found at the record name and write the
	// record in the target's zone instead of the original zone.
	// Default: true. Set to false to restore the previous behavior.
	FollowCNAME *bool `json:"follow_cname,omitempty"`

	logger *zap.Logger
}

func init() {
	caddy.RegisterModule(Provider{})
}

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.rfc2136",
		New: func() caddy.Module { return &Provider{Provider: new(rfc2136.Provider)} },
	}
}

func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			var dst *string
			switch d.Val() {
			case "key_name":
				dst = &p.KeyName
			case "key":
				dst = &p.Key
			case "key_alg":
				dst = &p.KeyAlg
			case "server":
				dst = &p.Server
			case "resolvers":
				for d.NextArg() {
					p.Resolvers = append(p.Resolvers, d.Val())
				}
				continue
			case "follow_cname":
				if !d.NextArg() {
					return d.ArgErr()
				}
				v, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid follow_cname value '%s': %v", d.Val(), err)
				}
				p.FollowCNAME = &v
				if d.NextArg() {
					return d.ArgErr()
				}
				continue
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}

			if d.NextArg() {
				*dst = d.Val()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		}
	}

	if p.Key == "" {
		return d.Err("rfc2136: missing key")
	}
	if p.KeyName == "" {
		return d.Err("rfc2136: missing key_name")
	}
	if p.KeyAlg == "" {
		return d.Err("rfc2136: missing key_alg")
	}
	if p.Server == "" {
		return d.Err("rfc2136: missing server")
	}

	return nil
}

func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()

	p.KeyName = repl.ReplaceAll(p.KeyName, "")
	p.Key = repl.ReplaceAll(p.Key, "")
	p.KeyAlg = repl.ReplaceAll(p.KeyAlg, "")
	p.Server = repl.ReplaceAll(p.Server, "")
	for i := range p.Resolvers {
		p.Resolvers[i] = repl.ReplaceAll(p.Resolvers[i], "")
	}

	p.logger = ctx.Logger(p)

	return nil
}

func (p *Provider) log() *zap.Logger {
	if p.logger == nil {
		return zap.NewNop()
	}
	return p.logger
}

func (p *Provider) followCNAME() bool {
	return p.FollowCNAME == nil || *p.FollowCNAME
}

// recursiveResolvers returns the resolvers to use for CNAME/SOA lookups,
// falling back to the system defaults exactly like certmagic does.
func (p *Provider) recursiveResolvers() []string {
	return certmagic.RecursiveNameservers(p.Resolvers)
}

const (
	maxCNAMEDepth   = 8
	dnsQueryTimeout = 10 * time.Second
)

// chaseCNAME follows the CNAME chain (if any) starting at fqdn and
// returns the final target FQDN, or "" if there is no CNAME at that
// name (or the lookup cannot be performed, in which case the caller
// proceeds with the original zone, i.e. the pre-existing behavior).
func (p *Provider) chaseCNAME(ctx context.Context, fqdn string) (string, error) {
	name := dns.Fqdn(fqdn)
	var finalTarget string

	for depth := 0; depth < maxCNAMEDepth; depth++ {
		msg := new(dns.Msg)
		msg.SetQuestion(name, dns.TypeCNAME)
		msg.SetEdns0(1232, false)

		var resp *dns.Msg
		var lastErr error
		for _, ns := range p.recursiveResolvers() {
			client := &dns.Client{Net: "udp", Timeout: dnsQueryTimeout}
			resp, _, lastErr = client.ExchangeContext(ctx, msg, ns)
			if lastErr == nil && resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
				break
			}
		}

		if resp == nil || (resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError) {
			// Lookup failed. If we already followed at least one CNAME,
			// use the last known target; otherwise fall back to the
			// original zone (pre-existing behavior).
			if finalTarget != "" {
				return finalTarget, nil
			}
			if lastErr != nil {
				p.log().Warn("rfc2136: CNAME lookup failed; writing to original zone",
					zap.String("name", name), zap.Error(lastErr))
			}
			return "", nil
		}

		var target string
		for _, ans := range resp.Answer {
			if cn, ok := ans.(*dns.CNAME); ok && cn.Hdr.Name == name {
				target = dns.Fqdn(cn.Target)
				break
			}
		}
		if target == "" {
			// Chain ends here (NXDOMAIN, or NOERROR without a CNAME).
			// Returns "" when there was no CNAME at all.
			return finalTarget, nil
		}

		p.log().Debug("rfc2136: following CNAME",
			zap.String("name", name), zap.String("target", target))
		finalTarget = target
		name = target
	}

	return "", fmt.Errorf("rfc2136: CNAME chain at %q exceeds maximum depth of %d", fqdn, maxCNAMEDepth)
}

// remapRecords rewrites each record so that it targets the zone of its
// CNAME's final target (when a CNAME exists at the record's absolute
// name), grouping records by the zone they must be written to. Zone
// discovery for the target uses certmagic's FindZoneByFQDN (SOA walk)
// and libdns' RelativeName helper, so no zone logic is reimplemented
// here.
//
// The rewritten records are used ONLY for the dynamic update sent to
// the DNS server. Callers (certmagic's DNSManager) always receive the
// original, un-rewritten records back, so its cleanup memory keeps the
// original zone+name pair and CleanUp re-derives the same delegated
// target as Present did. Returning the rewritten name here would make
// certmagic remember e.g. (zone=example.com, name=mtx), whose absolute
// name is the domain itself — whose own CNAME would then be followed
// on delete, removing records from the wrong zone (and leaking the
// delegated TXT records forever).
func (p *Provider) remapRecords(ctx context.Context, zone string, records []libdns.Record) (map[string][]libdns.Record, error) {
	zone = dns.Fqdn(zone)

	grouped := make(map[string][]libdns.Record, 1)
	for _, rec := range records {
		if !p.followCNAME() {
			grouped[zone] = append(grouped[zone], rec)
			continue
		}

		rr := rec.RR()
		absName := libdns.AbsoluteName(rr.Name, zone)

		target, err := p.chaseCNAME(ctx, absName)
		if err != nil {
			return nil, err
		}
		if target == "" {
			grouped[zone] = append(grouped[zone], rec)
			continue
		}

		targetZone, err := certmagic.FindZoneByFQDN(ctx, p.log(), target, p.recursiveResolvers())
		if err != nil {
			return nil, fmt.Errorf("rfc2136: determining zone for CNAME target %q of %q: %w", target, absName, err)
		}
		targetZone = dns.Fqdn(targetZone)

		rr.Name = libdns.RelativeName(target, targetZone)

		p.log().Info("rfc2136: following CNAME to delegated zone",
			zap.String("original_name", absName),
			zap.String("original_zone", zone),
			zap.String("target_name", target),
			zap.String("target_zone", targetZone))

		grouped[targetZone] = append(grouped[targetZone], rr)
	}

	return grouped, nil
}

type recordOp func(context.Context, string, []libdns.Record) ([]libdns.Record, error)

// applyPerZone performs the given libdns operation once per affected
// zone. The provider's return values are discarded: callers always get
// the original input records back (see the note on remapRecords), so
// certmagic's cleanup memory stays consistent with what Present was
// given.
func applyPerZone(ctx context.Context, original []libdns.Record, grouped map[string][]libdns.Record, op recordOp) ([]libdns.Record, error) {
	for _, z := range sortedZones(grouped) {
		if _, err := op(ctx, z, grouped[z]); err != nil {
			return nil, err
		}
	}
	return original, nil
}

func sortedZones(grouped map[string][]libdns.Record) []string {
	zones := make([]string, 0, len(grouped))
	for z := range grouped {
		zones = append(zones, z)
	}
	// deterministic iteration; typically len(zones) == 1
	for i := 1; i < len(zones); i++ {
		for j := i; j > 0 && zones[j] < zones[j-1]; j-- {
			zones[j], zones[j-1] = zones[j-1], zones[j]
		}
	}
	return zones
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	grouped, err := p.remapRecords(ctx, zone, records)
	if err != nil {
		return nil, err
	}
	return applyPerZone(ctx, records, grouped, p.Provider.AppendRecords)
}

func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	grouped, err := p.remapRecords(ctx, zone, records)
	if err != nil {
		return nil, err
	}
	return applyPerZone(ctx, records, grouped, p.Provider.SetRecords)
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	grouped, err := p.remapRecords(ctx, zone, records)
	if err != nil {
		return nil, err
	}
	return applyPerZone(ctx, records, grouped, p.Provider.DeleteRecords)
}

// GetRecords is intentionally *not* remapped: it lists a zone as-is and
// is not used by certmagic's DNS-01 solver (which needs
// RecordAppender + RecordDeleter only).

var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ certmagic.DNSProvider = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
