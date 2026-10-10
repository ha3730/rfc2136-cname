package caddy_dns_rfc2136

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/rfc2136"
	"github.com/miekg/dns"
)

// fakeDNS is a tiny authoritative-style server used to exercise the
// CNAME-following wrapper: it answers CNAME/SOA lookups (UDP) and
// accepts TSIG-signed dynamic updates (TCP), recording what it received.
type fakeDNS struct {
	mu      sync.Mutex
	updates []*dns.Msg

	cnames map[string]string // name -> target
	soas   map[string]string // zone -> mname
}

const (
	testKeyName = "testkey"
	testKeyB64  = "c3VwZXJzZWNyZXRrZXk=" // base64("supersecretkey")
)

func (f *fakeDNS) recordUpdate(m *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, m)
}

func (f *fakeDNS) popUpdates() []*dns.Msg {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.updates
	f.updates = nil
	return u
}

// acceptAllMsgs lets dynamic update (UPDATE opcode) messages through the
// server's default accept filter, which rejects them otherwise.
func acceptAllMsgs(dh dns.Header) dns.MsgAcceptAction {
	return dns.MsgAccept
}

func (f *fakeDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if r.Opcode == dns.OpcodeUpdate {
		if err := w.TsigStatus(); err != nil {
			m.SetRcode(r, dns.RcodeNotAuth)
			w.WriteMsg(m)
			return
		}
		f.recordUpdate(r)
		m.SetRcode(r, dns.RcodeSuccess)
		w.WriteMsg(m)
		return
	}

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]

	switch q.Qtype {
	case dns.TypeCNAME:
		if target, ok := f.cnames[q.Name]; ok {
			m.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: target,
			}}
		} else {
			m.SetRcode(r, dns.RcodeNameError)
		}
	case dns.TypeSOA:
		if mname, ok := f.soas[q.Name]; ok {
			m.Answer = []dns.RR{&dns.SOA{
				Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      mname,
				Mbox:    "admin." + q.Name,
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minttl:  300,
			}}
		} else {
			m.SetRcode(r, dns.RcodeNameError)
		}
	default:
		m.SetRcode(r, dns.RcodeNameError)
	}

	w.WriteMsg(m)
}

// startFakeDNS starts a UDP server (for CNAME/SOA lookups) and a TCP
// server (for TSIG-signed updates, as libdns/rfc2136 uses TCP) sharing
// one handler and one port.
func startFakeDNS(t *testing.T) (addr string, udpsrv, tcpsrv *dns.Server, store *fakeDNS) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr = ln.Addr().String()

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		ln.Close()
		t.Fatalf("listen udp: %v", err)
	}

	store = &fakeDNS{
		cnames: map[string]string{
			"_acme-challenge.example.com.":       "challenge.example.net.",
			"_acme-challenge.chain.example.com.": "hop1.example.net.",
			"hop1.example.net.":                  "hop2.example.org.",
			// apex CNAME: the domain itself has a CNAME pointing
			// into another zone
			"example.com.": "acme.example.net.",
		},
		soas: map[string]string{
			"example.com.": "ns1.example.com.",
			"example.net.": "ns1.example.net.",
		},
	}

	udpsrv = &dns.Server{
		PacketConn:    pc,
		Handler:       store,
		MsgAcceptFunc: acceptAllMsgs,
		TsigSecret:    map[string]string{dns.Fqdn(testKeyName): testKeyB64},
	}
	tcpsrv = &dns.Server{
		Listener:      ln,
		Net:           "tcp",
		Handler:       store,
		MsgAcceptFunc: acceptAllMsgs,
		TsigSecret:    map[string]string{dns.Fqdn(testKeyName): testKeyB64},
	}

	go func() {
		if err := udpsrv.ActivateAndServe(); err != nil {
			t.Errorf("udp server: %v", err)
		}
	}()
	go func() {
		if err := tcpsrv.ActivateAndServe(); err != nil {
			t.Errorf("tcp server: %v", err)
		}
	}()

	// wait for the TCP listener to be ready
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tcp server not ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	return addr, udpsrv, tcpsrv, store
}

func newTestProvider(addr string) *Provider {
	return &Provider{
		Provider: &rfc2136.Provider{
			KeyName: testKeyName,
			Key:     testKeyB64,
			KeyAlg:  "hmac-sha256",
			Server:  addr,
		},
		Resolvers: []string{addr},
	}
}

func challengeTXT(name string) libdns.RR {
	return libdns.RR{
		Type: "TXT",
		Name: name,
		Data: "test-validation-string",
		TTL:  120 * time.Second,
	}
}

// TestAppendFollowsCNAME: a CNAME exists at _acme-challenge.example.com.
// pointing into example.net. The update must land in zone example.net.
// with the record name rewritten to the CNAME target.
func TestAppendFollowsCNAME(t *testing.T) {
	addr, udpsrv, tcpsrv, store := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)

	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{challengeTXT("_acme-challenge")})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}

	updates := store.popUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	u := updates[0]

	if u.Question[0].Name != "example.net." {
		t.Errorf("update zone = %q, want example.net.", u.Question[0].Name)
	}

	got := rrNames(u.Ns)
	want := []string{"challenge.example.net."}
	if !equalStrings(got, want) {
		t.Errorf("update record names = %v, want %v", got, want)
	}
}

// TestAppendCNAMEChainZoneLookupFails: two-hop CNAME chain
// _acme-challenge.chain.example.com. -> hop1.example.net. -> hop2.example.org.
// The final target's zone (example.org.) has no SOA on the fake server,
// so zone discovery must fail with a clear error instead of silently
// writing to the wrong zone.
func TestAppendCNAMEChainZoneLookupFails(t *testing.T) {
	addr, udpsrv, tcpsrv, _ := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)

	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{challengeTXT("_acme-challenge.chain")})
	if err == nil {
		t.Fatal("expected error for unresolvable final zone, got nil")
	}
	t.Logf("expected error: %v", err)
}

// TestAppendNoCNAME: without a CNAME at the record name, behavior is
// unchanged — the update goes to the original zone.
func TestAppendNoCNAME(t *testing.T) {
	addr, udpsrv, tcpsrv, store := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)

	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{challengeTXT("_acme-challenge.sub")})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}

	updates := store.popUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if updates[0].Question[0].Name != "example.com." {
		t.Errorf("update zone = %q, want example.com.", updates[0].Question[0].Name)
	}
	if got, want := rrNames(updates[0].Ns), []string{"_acme-challenge.sub.example.com."}; !equalStrings(got, want) {
		t.Errorf("update record names = %v, want %v", got, want)
	}
}

// TestFollowCNAMEDisabled: follow_cname false restores old behavior.
func TestFollowCNAMEDisabled(t *testing.T) {
	addr, udpsrv, tcpsrv, store := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)
	off := false
	p.FollowCNAME = &off

	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{challengeTXT("_acme-challenge")})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}

	updates := store.popUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if updates[0].Question[0].Name != "example.com." {
		t.Errorf("update zone = %q, want example.com.", updates[0].Question[0].Name)
	}
}

// TestDeleteFollowsCNAME: certmagic's CleanUp (name+type, empty data =>
// RemoveRRset) must delete the TXT at the delegated zone.
func TestDeleteFollowsCNAME(t *testing.T) {
	addr, udpsrv, tcpsrv, store := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)

	rec := libdns.RR{Type: "TXT", Name: "_acme-challenge"}

	_, err := p.DeleteRecords(context.Background(), "example.com", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}

	updates := store.popUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	u := updates[0]

	if u.Question[0].Name != "example.net." {
		t.Errorf("update zone = %q, want example.net.", u.Question[0].Name)
	}
	if got, want := rrNames(u.Ns), []string{"challenge.example.net."}; !equalStrings(got, want) {
		t.Errorf("update names = %v, want %v", got, want)
	}
}

// TestPresentThenCleanupRoundTrip: regression test for the apex-CNAME
// scenario. The domain itself (example.com.) has a CNAME into another
// zone (acme.example.net.).
//
// certmagic's DNSManager stores whatever AppendRecords returns as its
// cleanup memory (paired with the ORIGINAL zone). If the wrapper returned
// the rewritten record (name="challenge"), cleanup would compute the
// absolute name "challenge.example.com." ... or worse, with name="mtx"
// style rewrites it would chase the domain's own CNAME and delete TXT
// records at acme.example.net. instead of the delegated challenge record.
//
// The wrapper must return the ORIGINAL records so cleanup re-derives the
// same delegated target as Present, and must never touch the domain's
// own CNAME target zone.
func TestPresentThenCleanupRoundTrip(t *testing.T) {
	addr, udpsrv, tcpsrv, store := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)
	ctx := context.Background()

	// Present: certmagic calls AppendRecords(zone=example.com,
	// name=_acme-challenge) and keeps the returned record.
	in := []libdns.Record{challengeTXT("_acme-challenge")}
	results, err := p.AppendRecords(ctx, "example.com", in)
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}

	// The update itself must land in the delegated zone...
	updates := store.popUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if updates[0].Question[0].Name != "example.net." {
		t.Errorf("present zone = %q, want example.net.", updates[0].Question[0].Name)
	}
	if got, want := rrNames(updates[0].Ns), []string{"challenge.example.net."}; !equalStrings(got, want) {
		t.Errorf("present names = %v, want %v", got, want)
	}

	// ...but the returned record must keep the original relative name,
	// exactly as certmagic passed it in.
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if rr := results[0].RR(); rr.Name != "_acme-challenge" || rr.Type != "TXT" {
		t.Fatalf("AppendRecords returned %+v, want original name=_acme-challenge type=TXT", rr)
	}

	// CleanUp: certmagic calls DeleteRecords with the ORIGINAL zone and
	// the record it got back. This must delete the delegated TXT...
	cleanupRec := results[0].RR()
	cleanupRec.Data = "" // certmagic's cleanUpRecord deletes by name+type
	if _, err := p.DeleteRecords(ctx, "example.com", []libdns.Record{cleanupRec}); err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}

	updates = store.popUpdates()
	if len(updates) != 1 {
		t.Fatalf("expected 1 cleanup update, got %d", len(updates))
	}
	u := updates[0]
	if u.Question[0].Name != "example.net." {
		t.Errorf("cleanup zone = %q, want example.net.", u.Question[0].Name)
	}
	if got, want := rrNames(u.Ns), []string{"challenge.example.net."}; !equalStrings(got, want) {
		t.Errorf("cleanup names = %v, want %v", got, want)
	}

	// ...and must NEVER touch the zone of the domain's own CNAME target
	// (acme.example.net.).
	for _, upd := range updates {
		for _, rr := range append(append([]dns.RR{}, upd.Ns...), upd.Answer...) {
			if strings.HasSuffix(rr.Header().Name, "acme.example.net.") {
				t.Errorf("cleanup touched domain CNAME target record: %s", rr.Header().Name)
			}
		}
	}
}

// TestTSIGRejected: the fake server requires a valid TSIG; a provider
// with a wrong key must fail (sanity check that the harness is real).
func TestTSIGRejected(t *testing.T) {
	addr, udpsrv, tcpsrv, _ := startFakeDNS(t)
	defer udpsrv.Shutdown()
	defer tcpsrv.Shutdown()

	p := newTestProvider(addr)
	p.Provider.Key = base64.StdEncoding.EncodeToString([]byte("wrongkey"))

	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{challengeTXT("_acme-challenge")})
	if err == nil {
		t.Fatal("expected TSIG failure, got nil")
	}
	t.Logf("expected error: %v", err)
}

func rrNames(rrs []dns.RR) []string {
	names := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		names = append(names, rr.Header().Name)
	}
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
