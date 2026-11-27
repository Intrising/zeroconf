package zeroconf

import (
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Intrising/dns"
	"github.com/pkg/errors"
)

var (
	mdnsName    = "test--xxxxxxxxxxxx"
	mdnsService = "_test--xxxx._tcp"
	mdnsSubtype = "_test--xxxx._tcp,_fancy"
	mdnsDomain  = "local."
	mdnsPort    = 8888
)

func startMDNS(ctx context.Context, port int, name, service, domain string) {
	// 5353 is default mdns port
	server, err := Register(name, service, domain, port, []string{"txtv=0", "lo=1", "la=2"}, nil)
	if err != nil {
		panic(errors.Wrap(err, "while registering mdns service"))
	}
	defer server.Shutdown()
	log.Printf("Published service: %s, type: %s, domain: %s", name, service, domain)

	<-ctx.Done()

	log.Printf("Shutting down.")

}

func TestBasic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go startMDNS(ctx, mdnsPort, mdnsName, mdnsService, mdnsDomain)

	time.Sleep(time.Second)

	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("Expected create resolver success, but got %v", err)
	}
	entries := make(chan *ServiceEntry, 100)
	if err := resolver.Browse(ctx, mdnsService, mdnsDomain, entries); err != nil {
		t.Fatalf("Expected browse success, but got %v", err)
	}
	<-ctx.Done()

	if len(entries) != 1 {
		t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
	}
	result := <-entries
	if result.Domain != mdnsDomain {
		t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
	}
	if result.Service != mdnsService {
		t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
	}
	if result.Instance != mdnsName {
		t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
	}
	if result.Port != mdnsPort {
		t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
	}
}

func TestNoRegister(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("Expected create resolver success, but got %v", err)
	}

	// before register, mdns resolve shuold not have any entry
	entries := make(chan *ServiceEntry)
	go func(results <-chan *ServiceEntry) {
		s := <-results
		if s != nil {
			t.Errorf("Expected empty service entries but got %v", *s)
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := resolver.Browse(ctx, mdnsService, mdnsDomain, entries); err != nil {
		t.Fatalf("Expected browse success, but got %v", err)
	}
	<-ctx.Done()
	cancel()
}

func TestSubtype(t *testing.T) {
	t.Run("browse with subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		go startMDNS(ctx, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		time.Sleep(time.Second)

		resolver, err := NewResolver(nil)
		if err != nil {
			t.Fatalf("Expected create resolver success, but got %v", err)
		}
		entries := make(chan *ServiceEntry, 100)
		if err := resolver.Browse(ctx, mdnsSubtype, mdnsDomain, entries); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}
		<-ctx.Done()

		if len(entries) != 1 {
			t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})

	t.Run("browse without subtype", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		go startMDNS(ctx, mdnsPort, mdnsName, mdnsSubtype, mdnsDomain)

		time.Sleep(time.Second)

		resolver, err := NewResolver(nil)
		if err != nil {
			t.Fatalf("Expected create resolver success, but got %v", err)
		}
		entries := make(chan *ServiceEntry, 100)
		if err := resolver.Browse(ctx, mdnsService, mdnsDomain, entries); err != nil {
			t.Fatalf("Expected browse success, but got %v", err)
		}
		<-ctx.Done()

		if len(entries) != 1 {
			t.Fatalf("Expected number of service entries is 1, but got %d", len(entries))
		}
		result := <-entries
		if result.Domain != mdnsDomain {
			t.Fatalf("Expected domain is %s, but got %s", mdnsDomain, result.Domain)
		}
		if result.Service != mdnsService {
			t.Fatalf("Expected service is %s, but got %s", mdnsService, result.Service)
		}
		if result.Instance != mdnsName {
			t.Fatalf("Expected instance is %s, but got %s", mdnsName, result.Instance)
		}
		if result.Port != mdnsPort {
			t.Fatalf("Expected port is %d, but got %d", mdnsPort, result.Port)
		}
	})
}

func rrHeader(name string, rrtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
}

const (
	tService = "_sntp._udp.local."
	tKey     = "peer_time._sntp._udp.local."
	tHost    = "host-peer.local."
)

func tParams(watch bool) (*lookupParams, chan *ServiceEntry, chan WatchEvent) {
	params := defaultParams("_sntp._udp")
	params.Domain = "local."
	params.isBrowsing = true
	entries := make(chan *ServiceEntry, 16)
	events := make(chan WatchEvent, 16)
	params.Entries = entries
	if watch {
		params.watch = true
		params.events = events
		params.queryInterval = 30 * time.Second
	}
	return params, entries, events
}

func tSRV(ttl uint32, priority, weight uint16) dns.RR {
	return &dns.SRV{Hdr: rrHeader(tKey, dns.TypeSRV, ttl), Priority: priority, Weight: weight, Port: 123, Target: tHost}
}
func tPTR(ttl uint32) dns.RR { return &dns.PTR{Hdr: rrHeader(tService, dns.TypePTR, ttl), Ptr: tKey} }
func tTXT(ttl uint32) dns.RR {
	return &dns.TXT{Hdr: rrHeader(tKey, dns.TypeTXT, ttl), Txt: []string{"txtvers=1"}}
}
func tA(ttl uint32, ip string) dns.RR {
	return &dns.A{Hdr: rrHeader(tHost, dns.TypeA, ttl), A: net.ParseIP(ip)}
}
func tAAAA(ttl uint32, ip string) dns.RR {
	return &dns.AAAA{Hdr: rrHeader(tHost, dns.TypeAAAA, ttl), AAAA: net.ParseIP(ip)}
}
func tMsg(rrs ...dns.RR) *dns.Msg { m := new(dns.Msg); m.Answer = rrs; return m }

// The entry TTL is the SRV TTL whatever the order and TTL of the PTR and TXT
// records; the SRV priority/weight reach the entry; without an SRV record the
// PTR TTL is used, as before.
func TestParseAnswersSRVFields(t *testing.T) {
	params, _, _ := tParams(false)

	a := parseAnswers(tMsg(tSRV(120, 10, 5), tPTR(4500), tTXT(4500), tA(120, "192.168.1.20")), params)[tKey]
	if a == nil {
		t.Fatalf("expected an answer for %s", tKey)
	}
	if a.entry.TTL != 120 || a.entry.Priority != 10 || a.entry.Weight != 5 {
		t.Fatalf("expected TTL 120, priority 10, weight 5, got %d/%d/%d", a.entry.TTL, a.entry.Priority, a.entry.Weight)
	}
	if a.entry.Instance != "peer_time" || len(a.entry.AddrIPv4) != 1 || a.goodbye {
		t.Fatalf("unexpected answer %+v / %+v", a, a.entry)
	}
	if !a.hasSRV || !a.hasTXT || !a.hasA || a.hasAAAA {
		t.Fatalf("unexpected parts: srv %v txt %v a %v aaaa %v", a.hasSRV, a.hasTXT, a.hasA, a.hasAAAA)
	}

	if got := parseAnswers(tMsg(tTXT(4500), tPTR(4500), tSRV(120, 10, 5)), params)[tKey].entry.TTL; got != 120 {
		t.Fatalf("SRV last: expected TTL 120, got %d", got)
	}
	if got := parseAnswers(tMsg(tPTR(4500)), params)[tKey].entry.TTL; got != 4500 {
		t.Fatalf("PTR only: expected TTL 4500, got %d", got)
	}
}

// A PTR or an SRV record with TTL 0 is a goodbye, also when the other records
// of the same packet still carry a TTL; a TXT record with TTL 0 next to a live
// SRV is not.
func TestParseAnswersGoodbye(t *testing.T) {
	params, _, _ := tParams(false)
	if !parseAnswers(tMsg(tPTR(0), tSRV(0, 0, 0), tTXT(0)), params)[tKey].goodbye {
		t.Fatalf("all records TTL 0 must be a goodbye")
	}
	if !parseAnswers(tMsg(tPTR(0), tSRV(120, 0, 0), tA(120, "192.168.1.20")), params)[tKey].goodbye {
		t.Fatalf("PTR TTL 0 with a live SRV must be a goodbye")
	}
	if !parseAnswers(tMsg(tPTR(4500), tSRV(0, 0, 0)), params)[tKey].goodbye {
		t.Fatalf("SRV TTL 0 must be a goodbye")
	}
	if parseAnswers(tMsg(tPTR(4500), tSRV(120, 0, 0), tTXT(0)), params)[tKey].goodbye {
		t.Fatalf("TXT TTL 0 next to a live SRV must not be a goodbye")
	}
}

// An address record with TTL 0 withdraws the address: it is not reported.
func TestParseAnswersWithdrawnAddress(t *testing.T) {
	params, _, _ := tParams(false)
	a := parseAnswers(tMsg(tSRV(120, 0, 0), tA(0, "192.168.1.20"), tA(120, "192.168.1.30")), params)[tKey]
	if len(a.entry.AddrIPv4) != 1 || a.entry.AddrIPv4[0].String() != "192.168.1.30" {
		t.Fatalf("expected only 192.168.1.30, got %v", a.entry.AddrIPv4)
	}
	if len(a.goneIPv4) != 1 || a.goneIPv4[0].String() != "192.168.1.20" {
		t.Fatalf("expected 192.168.1.20 as withdrawn, got %v", a.goneIPv4)
	}
}

// In watch mode an instance is reported on every answer, as the merged view:
// what a later, partial packet does not carry keeps its last known value.
func TestWatchReportsMergedView(t *testing.T) {
	params, _, events := tParams(true)
	st := newBrowseState()
	ctx := context.Background()
	now := time.Now()

	st.process(ctx, params, parseAnswers(tMsg(tPTR(4500), tSRV(120, 10, 5), tTXT(4500), tA(120, "192.168.1.20"), tAAAA(120, "fe80::1")), params), now)
	first := (<-events).Entry
	if first.TTL != 120 || len(first.AddrIPv4) != 1 || len(first.AddrIPv6) != 1 || len(first.Text) != 1 {
		t.Fatalf("unexpected first report %+v", first)
	}

	// SRV + AAAA only (for example the IPv6 copy of an answer).
	st.process(ctx, params, parseAnswers(tMsg(tSRV(120, 20, 5), tAAAA(120, "fe80::1")), params), now)
	ev := <-events
	if ev.Removed {
		t.Fatalf("a partial answer is not a goodbye")
	}
	second := ev.Entry
	if second.Priority != 20 {
		t.Fatalf("expected the new priority 20, got %d", second.Priority)
	}
	if len(second.AddrIPv4) != 1 || second.AddrIPv4[0].String() != "192.168.1.20" || len(second.Text) != 1 {
		t.Fatalf("the IPv4 address and TXT must be kept, got %v / %v", second.AddrIPv4, second.Text)
	}
	if second == first {
		t.Fatalf("each report must be its own copy")
	}

	// The old address is withdrawn and a new one announced in one packet.
	st.process(ctx, params, parseAnswers(tMsg(tSRV(120, 20, 5), tA(0, "192.168.1.20"), tA(120, "192.168.1.30")), params), now)
	third := (<-events).Entry
	if len(third.AddrIPv4) != 1 || third.AddrIPv4[0].String() != "192.168.1.30" {
		t.Fatalf("expected only the new address, got %v", third.AddrIPv4)
	}

	// The address is withdrawn without a replacement: IPv6 remains.
	st.process(ctx, params, parseAnswers(tMsg(tSRV(120, 20, 5), tA(0, "192.168.1.30")), params), now)
	fourth := (<-events).Entry
	if len(fourth.AddrIPv4) != 0 || len(fourth.AddrIPv6) != 1 {
		t.Fatalf("expected no IPv4 and one IPv6 address, got %v / %v", fourth.AddrIPv4, fourth.AddrIPv6)
	}
}

// A goodbye is reported once, in order with the reports, and only for an
// instance that has been reported.
func TestWatchGoodbye(t *testing.T) {
	params, _, events := tParams(true)
	st := newBrowseState()
	ctx := context.Background()
	now := time.Now()
	bye := func() { st.process(ctx, params, parseAnswers(tMsg(tPTR(0), tSRV(0, 0, 0), tTXT(0)), params), now) }
	hello := func() {
		st.process(ctx, params, parseAnswers(tMsg(tPTR(4500), tSRV(120, 0, 0), tA(120, "192.168.1.20")), params), now)
	}

	bye() // never reported
	if len(events) != 0 {
		t.Fatalf("a goodbye for an instance never reported must not be delivered")
	}

	hello()
	bye()
	bye() // repetition (second socket, repeated goodbye)
	hello()
	want := []bool{false, true, false}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i, removed := range want {
		ev := <-events
		if ev.Removed != removed || ev.Entry.Instance != "peer_time" {
			t.Fatalf("event %d: expected removed=%v for peer_time, got %+v", i, removed, ev)
		}
	}
}

// Browse keeps reporting an instance once, and drops it silently on goodbye.
func TestBrowseReportsOnce(t *testing.T) {
	params, entries, events := tParams(false)
	st := newBrowseState()
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < 3; i++ {
		st.process(ctx, params, parseAnswers(tMsg(tPTR(4500), tSRV(120, 0, 0), tA(120, "192.168.1.20")), params), now)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one report, got %d", len(entries))
	}
	st.process(ctx, params, parseAnswers(tMsg(tPTR(0), tSRV(0, 0, 0)), params), now)
	st.process(ctx, params, parseAnswers(tMsg(tPTR(4500), tSRV(120, 0, 0), tA(120, "192.168.1.20")), params), now)
	if len(entries) != 2 || len(events) != 0 {
		t.Fatalf("after goodbye and re-announcement: expected 2 reports and no event, got %d / %d", len(entries), len(events))
	}
}

// A subscriber that stopped reading cannot hold the receive loop once the
// context is done.
func TestProcessDoesNotBlockAfterCancel(t *testing.T) {
	params := defaultParams("_sntp._udp")
	params.Domain = "local."
	params.isBrowsing = true
	params.Entries = make(chan *ServiceEntry) // unbuffered, nobody reads
	st := newBrowseState()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		st.process(ctx, params, parseAnswers(tMsg(tPTR(4500), tSRV(120, 0, 0), tA(120, "192.168.1.20")), params), time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("process blocked on a subscriber that is gone")
	}
}

// In watch mode instances that are no longer heard are forgotten after their
// TTL, so the state does not grow without bound.
func TestWatchStatePurge(t *testing.T) {
	params, _, events := tParams(true)
	st := newBrowseState()
	ctx := context.Background()
	t0 := time.Now()
	st.process(ctx, params, parseAnswers(tMsg(tPTR(4500), tSRV(120, 0, 0), tA(120, "192.168.1.20")), params), t0)
	<-events
	if len(st.known) != 1 {
		t.Fatalf("expected one known instance, got %d", len(st.known))
	}
	// Another message, long after the first instance's TTL.
	st.process(ctx, params, map[string]*answer{}, t0.Add(200*time.Second))
	if len(st.known) != 0 || len(st.reported) != 0 || len(st.heard) != 0 {
		t.Fatalf("expected the silent instance to be forgotten, got %d/%d/%d", len(st.known), len(st.reported), len(st.heard))
	}
}

// TestWatch registers a service, watches it, expects the same instance to be
// reported more than once (kick sends a query at once), then shuts the server
// down and expects the goodbye event.
func TestWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	name := "test--watch-xxxx"
	server, err := Register(name, mdnsService, mdnsDomain, mdnsPort, []string{"txtv=0"}, nil)
	if err != nil {
		t.Fatalf("Expected register success, but got %v", err)
	}
	time.Sleep(time.Second)

	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("Expected create resolver success, but got %v", err)
	}
	events := make(chan WatchEvent, 100)
	kick := make(chan struct{}, 1)
	if err := resolver.Watch(ctx, mdnsService, mdnsDomain, time.Hour, kick, events); err != nil {
		t.Fatalf("Expected watch success, but got %v", err)
	}

	next := func(what string) WatchEvent {
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					t.Fatalf("events closed while waiting for %s", what)
				}
				if ev.Entry.Instance == name {
					return ev
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	if ev := next("the first report"); ev.Removed {
		t.Fatalf("expected a report first, got a goodbye")
	}
	// With an interval of one hour only the kick can cause a second answer.
	time.Sleep(1500 * time.Millisecond) // let the server's own announcements pass
	for len(events) > 0 {
		<-events
	}
	kick <- struct{}{}
	if ev := next("the report after the kick"); ev.Removed {
		t.Fatalf("expected a report after the kick, got a goodbye")
	}

	server.Shutdown()
	for !next("the goodbye").Removed {
	}

	// The watch ends with the context: events gets closed.
	cancel()
	for range events {
	}
}

// When every receive socket has failed the watch ends: events is closed and
// the query loop stops.
func TestWatchEndsWhenReceiversFail(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("Expected create resolver success, but got %v", err)
	}
	events := make(chan WatchEvent, 100)
	if err := resolver.Watch(context.Background(), mdnsService, mdnsDomain, time.Hour, nil, events); err != nil {
		t.Fatalf("Expected watch success, but got %v", err)
	}
	if resolver.c.ipv4conn != nil {
		resolver.c.ipv4conn.Close()
	}
	if resolver.c.ipv6conn != nil {
		resolver.c.ipv6conn.Close()
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatalf("events was not closed after the receive sockets failed")
		}
	}
}

// Bad arguments are refused before anything is started.
func TestWatchArguments(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("Expected create resolver success, but got %v", err)
	}
	defer resolver.c.shutdown()
	events := make(chan WatchEvent, 1)
	if err := resolver.Watch(context.Background(), mdnsService, mdnsDomain, 0, nil, events); err == nil {
		t.Fatalf("expected an error for a zero interval")
	}
	if err := resolver.Watch(context.Background(), mdnsService, mdnsDomain, time.Second, nil, nil); err == nil {
		t.Fatalf("expected an error for a nil events channel")
	}
}
