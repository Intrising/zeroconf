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

// answerMsg builds one mDNS answer for an instance of _sntp._udp.local.
func answerMsg(instance string, ptrTTL, srvTTL, txtTTL uint32, priority, weight uint16) *dns.Msg {
	service := "_sntp._udp.local."
	full := instance + "." + service
	host := "host-" + instance + ".local."
	m := new(dns.Msg)
	m.Answer = []dns.RR{
		&dns.SRV{Hdr: rrHeader(full, dns.TypeSRV, srvTTL), Priority: priority, Weight: weight, Port: 123, Target: host},
		&dns.PTR{Hdr: rrHeader(service, dns.TypePTR, ptrTTL), Ptr: full},
		&dns.TXT{Hdr: rrHeader(full, dns.TypeTXT, txtTTL), Txt: []string{"txtvers=1"}},
	}
	m.Extra = []dns.RR{&dns.A{Hdr: rrHeader(host, dns.TypeA, srvTTL), A: net.ParseIP("192.168.1.20")}}
	return m
}

// The entry TTL is the SRV TTL whatever the order and TTL of the PTR and TXT
// records, and the SRV priority/weight reach the entry.
func TestParseAnswersSRVFields(t *testing.T) {
	params := defaultParams("_sntp._udp")
	params.Domain = "local."
	key := "peer_time._sntp._udp.local."

	entries := parseAnswers(answerMsg("peer_time", 4500, 120, 4500, 10, 5), params)
	e, ok := entries[key]
	if !ok {
		t.Fatalf("expected entry %s, got %v", key, entries)
	}
	if e.TTL != 120 {
		t.Fatalf("expected TTL 120 (SRV), got %d", e.TTL)
	}
	if e.Priority != 10 || e.Weight != 5 {
		t.Fatalf("expected priority/weight 10/5, got %d/%d", e.Priority, e.Weight)
	}
	if e.Instance != "peer_time" || len(e.AddrIPv4) != 1 {
		t.Fatalf("unexpected entry %+v", e)
	}

	// SRV first or last in the message makes no difference.
	m := answerMsg("peer_time", 4500, 120, 4500, 10, 5)
	m.Answer[0], m.Answer[2] = m.Answer[2], m.Answer[0]
	if got := parseAnswers(m, params)[key].TTL; got != 120 {
		t.Fatalf("SRV last: expected TTL 120, got %d", got)
	}

	// A goodbye carries TTL 0 on every record.
	if got := parseAnswers(answerMsg("peer_time", 0, 0, 0, 10, 5), params)[key].TTL; got != 0 {
		t.Fatalf("goodbye: expected TTL 0, got %d", got)
	}

	// Without an SRV record the PTR TTL is used, as before.
	m = answerMsg("peer_time", 4500, 120, 4500, 10, 5)
	m.Answer = m.Answer[1:2]
	if got := parseAnswers(m, params)[key].TTL; got != 4500 {
		t.Fatalf("PTR only: expected TTL 4500, got %d", got)
	}
}

// TestWatch registers a service, watches it, expects the same instance to be
// reported more than once (one report per repeated query), then shuts the
// server down and expects the goodbye on removed.
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
	updates := make(chan *ServiceEntry, 100)
	removed := make(chan *ServiceEntry, 100)
	if err := resolver.Watch(ctx, mdnsService, mdnsDomain, time.Second, updates, removed); err != nil {
		t.Fatalf("Expected watch success, but got %v", err)
	}

	seen := 0
	for seen < 2 {
		select {
		case e, ok := <-updates:
			if !ok {
				t.Fatalf("updates closed early")
			}
			if e.Instance == name {
				seen++
			}
		case <-ctx.Done():
			t.Fatalf("expected the instance to be reported at least twice, got %d", seen)
		}
	}

	server.Shutdown()

	for {
		select {
		case e := <-removed:
			if e.Instance == name {
				// The watch ends with the context: updates gets closed.
				cancel()
				for range updates {
				}
				return
			}
		case <-updates:
		case <-ctx.Done():
			t.Fatalf("Goodbye was not reported")
		}
	}
}

// A non-positive interval is refused.
func TestWatchInterval(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("Expected create resolver success, but got %v", err)
	}
	updates := make(chan *ServiceEntry, 1)
	if err := resolver.Watch(context.Background(), mdnsService, mdnsDomain, 0, updates, nil); err == nil {
		t.Fatalf("expected an error for a zero interval")
	}
}
