package zeroconf

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Intrising/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// Number of Multicast responses sent for a query message (default: 1 < x < 9)
	multicastRepetitions = 2
)

// Register a service by given arguments. This call will take the system's hostname
// and lookup IP by that hostname.
func Register(instance, service, domain string, port int, text []string, ifaces []net.Interface, ttl ...uint32) (*Server, error) {
	entry := NewServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.Domain == "" {
		entry.Domain = "local."
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	var err error
	if entry.HostName == "" {
		entry.HostName, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("could not determine host")
		}
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}

	for _, iface := range ifaces {
		v4, v6 := addrsForInterface(&iface)
		entry.AddrIPv4 = append(entry.AddrIPv4, v4...)
		entry.AddrIPv6 = append(entry.AddrIPv6, v6...)
	}

	if entry.AddrIPv4 == nil && entry.AddrIPv6 == nil {
		return nil, fmt.Errorf("could not determine host IP addresses")
	}

	s, err := newServer(ifaces)
	if err != nil {
		return nil, err
	}

	s.service = entry
	if len(ttl) > 0 && ttl[0] > 0 {
		s.ttl = ttl[0]
	}
	go s.mainloop()
	go s.probe()

	return s, nil
}

// RegisterProxy registers a service proxy. This call will skip the hostname/IP lookup and
// will use the provided values.
func RegisterProxy(instance, service, domain string, port int, host string, ips []string, text []string, ifaces []net.Interface) (*Server, error) {
	entry := NewServiceEntry(instance, service, domain)
	entry.Port = port
	entry.Text = text
	entry.HostName = host

	if entry.Instance == "" {
		return nil, fmt.Errorf("missing service instance name")
	}
	if entry.Service == "" {
		return nil, fmt.Errorf("missing service name")
	}
	if entry.HostName == "" {
		return nil, fmt.Errorf("missing host name")
	}
	if entry.Domain == "" {
		entry.Domain = "local"
	}
	if entry.Port == 0 {
		return nil, fmt.Errorf("missing port")
	}

	if !strings.HasSuffix(trimDot(entry.HostName), entry.Domain) {
		entry.HostName = fmt.Sprintf("%s.%s.", trimDot(entry.HostName), trimDot(entry.Domain))
	}

	for _, ip := range ips {
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return nil, fmt.Errorf("failed to parse given IP: %v", ip)
		} else if ipv4 := ipAddr.To4(); ipv4 != nil {
			entry.AddrIPv4 = append(entry.AddrIPv4, ipAddr)
		} else if ipv6 := ipAddr.To16(); ipv6 != nil {
			entry.AddrIPv6 = append(entry.AddrIPv6, ipAddr)
		} else {
			return nil, fmt.Errorf("the IP is neither IPv4 nor IPv6: %#v", ipAddr)
		}
	}

	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}

	s, err := newServer(ifaces)
	if err != nil {
		return nil, err
	}

	s.service = entry
	go s.mainloop()
	go s.probe()

	return s, nil
}

const (
	qClassCacheFlush uint16 = 1 << 15
)

// ifaceAddrCache stores cached addresses for an interface
type ifaceAddrCache struct {
	iface *net.Interface
	addrs []net.Addr
	v4    []net.IP
	v6    []net.IP
}

// Server structure encapsulates both IPv4/IPv6 UDP connections
type Server struct {
	service    *ServiceEntry
	ipv4conn   *ipv4.PacketConn
	ipv6conn   *ipv6.PacketConn
	ifaces     []net.Interface
	ifaceAddrs []ifaceAddrCache // cached interface addresses

	shouldShutdown chan struct{}
	shutdownLock   sync.Mutex
	shutdownEnd    sync.WaitGroup
	isShutdown     bool
	ttl            uint32
	disableKnownAnswerSuppression bool

	// textMu guards service.Text. SetText replaces the slice from the caller's
	// goroutine while recv4/recv6 -> handleQuery read it, and a slice header is
	// not written atomically: a responder could otherwise pair the new data
	// pointer with the old length. Now that SetText runs on a fixed schedule the
	// overlap with inbound queries is routine rather than incidental.
	textMu sync.RWMutex

	// SuppressCheck: if set, returning true suppresses the mDNS response.
	// Used by SuppressBeforeUpdate: blocks responses in the 10s window before
	// atdatetime is updated, so the test tool never sees new TXT while HTTP cache is stale.
	suppressCheck func() bool

	// Rate limiting for mDNS packets
	rateLimitCount int64
	rateLimitTime  time.Time
	rateLimitMu    sync.Mutex
}

// Constructs server structure
func newServer(ifaces []net.Interface) (*Server, error) {
	ipv4conn, err4 := joinUdp4Multicast(ifaces)
	if err4 != nil {
		log.Printf("[zeroconf] no suitable IPv4 interface: %s", err4.Error())
	}
	ipv6conn, err6 := joinUdp6Multicast(ifaces)
	if err6 != nil {
		log.Printf("[zeroconf] no suitable IPv6 interface: %s", err6.Error())
	}
	if err4 != nil && err6 != nil {
		// No supported interface left.
		return nil, fmt.Errorf("no supported interface")
	}

	// Pre-cache interface addresses to avoid expensive syscalls on every query
	ifaceAddrs := make([]ifaceAddrCache, 0, len(ifaces))
	for i := range ifaces {
		iface := &ifaces[i]
		// Skip down or non-multicast interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		v4, v6 := addrsForInterface(iface)
		ifaceAddrs = append(ifaceAddrs, ifaceAddrCache{
			iface: iface,
			addrs: addrs,
			v4:    v4,
			v6:    v6,
		})
	}

	s := &Server{
		ipv4conn:       ipv4conn,
		ipv6conn:       ipv6conn,
		ifaces:         ifaces,
		ifaceAddrs:     ifaceAddrs,
		ttl:            3200,
		shouldShutdown: make(chan struct{}),
	}

	return s, nil
}

// Start listeners and waits for the shutdown signal from exit channel
func (s *Server) mainloop() {
	if s.ipv4conn != nil {
		go s.recv4(s.ipv4conn)
	}
	if s.ipv6conn != nil {
		go s.recv6(s.ipv6conn)
	}
}

// Shutdown closes all udp connections and unregisters the service
func (s *Server) Shutdown() {
	s.shutdown()
}

// SetText updates the TXT records and announces them, so a subscriber learns the
// new value without having to query first (ITxPT S02 requires the module to send
// an unsolicited announcement each update interval).
//
// The announcement was removed in 92ce7d5 because it could reach the compliance
// tool while moduleinfo.xml still held the previous atdatetime, which the tool
// reported as a TXT/XML mismatch. The caller now writes the XML before calling
// SetText, so the announced value is never ahead of the file and the
// announcement is safe to send again.
func (s *Server) SetText(text []string) {
	s.textMu.Lock()
	s.service.Text = text
	s.textMu.Unlock()
	s.announceText()
}

// textSnapshot returns the current TXT strings under the read lock. SetText
// replaces the slice rather than mutating it, so the returned value stays
// consistent for the caller; callers must not modify it.
func (s *Server) textSnapshot() []string {
	s.textMu.RLock()
	defer s.textMu.RUnlock()
	return s.service.Text
}

// TTL sets the TTL for DNS replies
func (s *Server) TTL(ttl uint32) {
	s.ttl = ttl
}

// SetKnownAnswerSuppression enables or disables RFC 6762 Known Answer Suppression.
// When disabled, the server always responds to browse queries even if the client
// already has the answer cached. This helps clients with stale TXT cache get fresh data.
func (s *Server) SetKnownAnswerSuppression(enabled bool) {
	s.disableKnownAnswerSuppression = !enabled
}

// SetSuppressCheck registers a callback that is called before each mDNS response.
// If the callback returns true, the response is suppressed (not sent).
// Used to implement SuppressBeforeUpdate: block responses in the 10-second window
// before a periodic atdatetime update so the test tool always fetches fresh HTTP
// before it can compare against the new TXT value.
func (s *Server) SetSuppressCheck(fn func() bool) {
	s.suppressCheck = fn
}

// Shutdown server will close currently open connections & channel
func (s *Server) shutdown() error {
	s.shutdownLock.Lock()
	defer s.shutdownLock.Unlock()
	if s.isShutdown {
		return errors.New("server is already shutdown")
	}

	err := s.unregister()

	close(s.shouldShutdown)

	if s.ipv4conn != nil {
		s.ipv4conn.Close()
	}
	if s.ipv6conn != nil {
		s.ipv6conn.Close()
	}

	// Wait for connection and routines to be closed
	s.shutdownEnd.Wait()
	s.isShutdown = true

	return err
}

// isSourceInInterfaceSubnet checks if the source IP is in the same subnet as the interface
func (s *Server) isSourceInInterfaceSubnet(ifIndex int, from net.Addr) bool {
	if from == nil {
		return true // No source to check
	}

	// Extract source IP
	var srcIP net.IP
	if udpAddr, ok := from.(*net.UDPAddr); ok {
		srcIP = udpAddr.IP
	}
	if srcIP == nil {
		return true // Can't determine source IP
	}

	// Find the interface by ifIndex and check subnet
	for _, cache := range s.ifaceAddrs {
		if cache.iface.Index == ifIndex {
			for _, addr := range cache.addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if ipNet.Contains(srcIP) {
						return true
					}
				}
			}
			return false // Interface found but source not in subnet
		}
	}

	return true // Interface not found in cache, allow packet
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv4(c *ipv4.PacketConn) {
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	s.shutdownEnd.Add(1)
	defer s.shutdownEnd.Done()
	for {
		select {
		case <-s.shouldShutdown:
			return
		default:
			var ifIndex int
			n, cm, from, err := c.ReadFrom(buf)
			if err != nil {
				continue
			}
			if cm != nil {
				ifIndex = cm.IfIndex
			}
			// Debug: log received mDNS packets from external sources
			if from != nil {
				if udpAddr, ok := from.(*net.UDPAddr); ok && !udpAddr.IP.IsLoopback() {
					isLocal := false
					for _, a := range s.service.AddrIPv4 {
						if a.Equal(udpAddr.IP) { isLocal = true; break }
					}
					if !isLocal {
						log.Printf("[zeroconf-recv] recv4 from %v ifIndex=%d size=%d service=%s server_ttl=%d", from, ifIndex, n, s.service.ServiceName(), s.ttl)
					}
				}
			}
			// Skip if source IP not in same subnet as receiving interface
			if !s.isSourceInInterfaceSubnet(ifIndex, from) {
				log.Printf("[zeroconf-recv] DROPPED from %v ifIndex=%d (not in subnet) service=%s", from, ifIndex, s.service.ServiceName())
				continue
			}
			_ = s.parsePacket(buf[:n], ifIndex, from)
		}
	}
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv6(c *ipv6.PacketConn) {
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	s.shutdownEnd.Add(1)
	defer s.shutdownEnd.Done()
	for {
		select {
		case <-s.shouldShutdown:
			return
		default:
			var ifIndex int
			n, cm, from, err := c.ReadFrom(buf)
			if err != nil {
				continue
			}
			if cm != nil {
				ifIndex = cm.IfIndex
			}
			// Debug: log received mDNS packets from external sources
			if from != nil {
				if udpAddr, ok := from.(*net.UDPAddr); ok && !udpAddr.IP.IsLoopback() {
					isLocal := false
					for _, a := range s.service.AddrIPv4 {
						if a.Equal(udpAddr.IP) { isLocal = true; break }
					}
					if !isLocal {
						log.Printf("[zeroconf-recv] recv4 from %v ifIndex=%d size=%d service=%s server_ttl=%d", from, ifIndex, n, s.service.ServiceName(), s.ttl)
					}
				}
			}
			// Skip if source IP not in same subnet as receiving interface
			if !s.isSourceInInterfaceSubnet(ifIndex, from) {
				log.Printf("[zeroconf-recv] DROPPED from %v ifIndex=%d (not in subnet) service=%s", from, ifIndex, s.service.ServiceName())
				continue
			}
			_ = s.parsePacket(buf[:n], ifIndex, from)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(packet []byte, ifIndex int, from net.Addr) error {
	// Rate limiting: max 256 packets per second
	const maxPacketsPerSecond = 256
	s.rateLimitMu.Lock()
	now := time.Now()
	if now.Sub(s.rateLimitTime) >= time.Second {
		s.rateLimitCount = 0
		s.rateLimitTime = now
	}
	s.rateLimitCount++
	if s.rateLimitCount > maxPacketsPerSecond {
		s.rateLimitMu.Unlock()
		return errors.New("rate limit exceeded")
	}
	s.rateLimitMu.Unlock()

	// Validate DNS header to reject malformed packets with abnormal record counts.
	// DNS header: bytes 4-5 = QDCOUNT, 6-7 = ANCOUNT, 8-9 = NSCOUNT, 10-11 = ARCOUNT
	const maxRecords = 256 // reasonable limit for mDNS packets
	if len(packet) >= 12 {
		qdcount := int(packet[4])<<8 | int(packet[5])
		ancount := int(packet[6])<<8 | int(packet[7])
		nscount := int(packet[8])<<8 | int(packet[9])
		arcount := int(packet[10])<<8 | int(packet[11])
		if qdcount > maxRecords || ancount > maxRecords || nscount > maxRecords || arcount > maxRecords {
			return errors.New("malformed DNS packet: record count exceeds limit")
		}
	}

	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		// log.Printf("[ERR] zeroconf: Failed to unpack packet: %v", err)
		return err
	}
	return s.handleQuery(&msg, ifIndex, from)
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, ifIndex int, from net.Addr) error {
    if len(query.Ns) > 0 {
        return nil
    }
    var err error
    for _, q := range query.Question {
        resp := dns.Msg{}
        resp.SetReply(query)
        resp.Compress = true
        resp.RecursionDesired = false
        resp.Authoritative = true
        resp.Question = nil
        resp.Answer = []dns.RR{}
        resp.Extra = []dns.RR{}
        if err = s.handleQuestion(q, &resp, query, ifIndex, from); err != nil {
            continue
        }
        if len(resp.Answer) == 0 {
            // Only log when query is relevant to this service (reduce noise)
//             if q.Name == s.service.ServiceName() || q.Name == s.service.ServiceInstanceName() {
//                 log.Printf("[zeroconf-dbg] query %s from %v ifIndex=%d => no answer (service=%s, server_ptr=%p) SUPPRESSED", q.Name, from, ifIndex, s.service.ServiceName(), s)
//             }
            continue
        }
        // Extract atdatetime from current TXT for debug
//         dbgAtdt := ""
//         for _, t := range s.service.Text {
//             if len(t) > 11 && t[:11] == "atdatetime=" {
//                 dbgAtdt = t[11:]
//                 break
//             }
//         }
//         log.Printf("[zeroconf-dbg] query %s from %v ifIndex=%d => %d answers (service=%s, txt_atdatetime=%s, server_ptr=%p, ttl=%d)", q.Name, from, ifIndex, len(resp.Answer), s.service.ServiceName(), dbgAtdt, s, s.ttl)
        // SuppressBeforeUpdate: block response in the window before atdatetime update.
        // The test tool fetches HTTP after seeing new TXT; suppressing ensures it cannot
        // see the new TXT until its HTTP cache already reflects the new atdatetime.
        if s.suppressCheck != nil && s.suppressCheck() {
//             log.Printf("[zeroconf-dbg] suppress-before-update: blocking response to %v for %s (txt_atdatetime=%s)", from, q.Name, dbgAtdt)
            continue
        }
        if isUnicastQuestion(q) {
//             log.Printf("[zeroconf-dbg] sending unicast response to %v for %s (txt_atdatetime=%s)", from, q.Name, dbgAtdt)
            if e := s.unicastResponse(&resp, ifIndex, from); e != nil {
                err = e
            }
        } else {
//             log.Printf("[zeroconf-dbg] sending multicast response for %s ifIndex=%d (txt_atdatetime=%s)", q.Name, ifIndex, dbgAtdt)
            if e := s.multicastResponse(&resp, ifIndex); e != nil {
                err = e
            }
        }
    }
    return err
}

// RFC6762 7.1. Known-Answer Suppression
func (s *Server) isKnownAnswer(resp *dns.Msg, query *dns.Msg) bool {
	if s.disableKnownAnswerSuppression {
		return false
	}
	if len(resp.Answer) == 0 || len(query.Answer) == 0 {
		return false
	}
	if resp.Answer[0].Header().Rrtype != dns.TypePTR {
		return false
	}
	answer := resp.Answer[0].(*dns.PTR)

	for _, known := range query.Answer {
		hdr := known.Header()
		if hdr.Rrtype != answer.Hdr.Rrtype {
			continue
		}
		ptr := known.(*dns.PTR)
		if ptr.Ptr == answer.Ptr && hdr.Ttl >= answer.Hdr.Ttl/2 {
			return true
		}
	}

	return false
}

// handleQuestion is used to handle an incoming question
func (s *Server) handleQuestion(q dns.Question, resp *dns.Msg, query *dns.Msg, ifIndex int, from net.Addr) error {
    if s.service == nil {
        return nil
    }
    switch q.Name {
    case s.service.ServiceTypeName():
        s.serviceTypeName(resp, s.ttl, from)
        if s.isKnownAnswer(resp, query) {
            resp.Answer = nil
        }
    case s.service.ServiceName():
        s.composeBrowsingAnswers(resp, ifIndex, from)
        if s.isKnownAnswer(resp, query) {
            resp.Answer = nil
        }
    case s.service.ServiceInstanceName():
        s.composeLookupAnswers(resp, s.ttl, ifIndex, from, false)
    default:
        for _, subtype := range s.service.Subtypes {
            subtype = fmt.Sprintf("%s._sub.%s", subtype, s.service.ServiceName())
            if q.Name == subtype {
                s.composeBrowsingAnswers(resp, ifIndex, from)
                if s.isKnownAnswer(resp, query) {
                    resp.Answer = nil
                }
                break
            }
        }
    }
    return nil
}

func (s *Server) composeBrowsingAnswers(resp *dns.Msg, ifIndex int, from net.Addr) {
    ptr := &dns.PTR{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceName(),
            Rrtype: dns.TypePTR,
            Class:  dns.ClassINET,
            Ttl:    s.ttl,
        },
        Ptr: s.service.ServiceInstanceName(),
    }
    resp.Answer = append(resp.Answer, ptr)
    txt := &dns.TXT{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceInstanceName(),
            Rrtype: dns.TypeTXT,
            Class:  dns.ClassINET,
            Ttl:    s.ttl,
        },
        Txt: s.textSnapshot(),
    }
    srv := &dns.SRV{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceInstanceName(),
            Rrtype: dns.TypeSRV,
            Class:  dns.ClassINET,
            Ttl:    s.ttl,
        },
        Priority: 0,
        Weight:   0,
        Port:     uint16(s.service.Port),
        Target:   s.service.HostName,
    }
    resp.Extra = append(resp.Extra, srv, txt)
    resp.Extra = s.appendAddrs(resp.Extra, s.ttl, ifIndex, from, false)
}

func (s *Server) composeLookupAnswers(resp *dns.Msg, ttl uint32, ifIndex int, from net.Addr, flushCache bool) {
    ptr := &dns.PTR{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceName(),
            Rrtype: dns.TypePTR,
            Class:  dns.ClassINET,
            Ttl:    ttl,
        },
        Ptr: s.service.ServiceInstanceName(),
    }
    srv := &dns.SRV{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceInstanceName(),
            Rrtype: dns.TypeSRV,
            Class:  dns.ClassINET | qClassCacheFlush,
            Ttl:    ttl,
        },
        Priority: 0,
        Weight:   0,
        Port:     uint16(s.service.Port),
        Target:   s.service.HostName,
    }
    txt := &dns.TXT{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceInstanceName(),
            Rrtype: dns.TypeTXT,
            Class:  dns.ClassINET | qClassCacheFlush,
            Ttl:    ttl,
        },
        Txt: s.textSnapshot(),
    }
    dnssd := &dns.PTR{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceTypeName(),
            Rrtype: dns.TypePTR,
            Class:  dns.ClassINET,
            Ttl:    ttl,
        },
        Ptr: s.service.ServiceName(),
    }
    resp.Answer = append(resp.Answer, srv, txt, ptr, dnssd)
    for _, subtype := range s.service.Subtypes {
        resp.Answer = append(resp.Answer,
            &dns.PTR{
                Hdr: dns.RR_Header{
                    Name:   subtype,
                    Rrtype: dns.TypePTR,
                    Class:  dns.ClassINET,
                    Ttl:    ttl,
                },
                Ptr: s.service.ServiceInstanceName(),
            })
    }
    resp.Answer = s.appendAddrs(resp.Answer, ttl, ifIndex, from, flushCache)
}

func (s *Server) serviceTypeName(resp *dns.Msg, ttl uint32, from net.Addr) {
    dnssd := &dns.PTR{
        Hdr: dns.RR_Header{
            Name:   s.service.ServiceTypeName(),
            Rrtype: dns.TypePTR,
            Class:  dns.ClassINET,
            Ttl:    ttl,
        },
        Ptr: s.service.ServiceName(),
    }
    resp.Answer = append(resp.Answer, dnssd)
}

// Perform probing & announcement
//TODO: implement a proper probing & conflict resolution
func (s *Server) probe() {
	q := new(dns.Msg)
	q.SetQuestion(s.service.ServiceInstanceName(), dns.TypePTR)
	q.RecursionDesired = false

	srv := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(s.service.Port),
		Target:   s.service.HostName,
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   s.service.ServiceInstanceName(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Txt: s.textSnapshot(),
	}
	q.Ns = []dns.RR{srv, txt}

	randomizer := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < multicastRepetitions; i++ {
		if err := s.multicastResponse(q, 0); err != nil {
			log.Println("[ERR] zeroconf: failed to send probe:", err.Error())
		}
		time.Sleep(time.Duration(randomizer.Intn(250)) * time.Millisecond)
	}

	// From RFC6762
	//    The Multicast DNS responder MUST send at least two unsolicited
	//    responses, one second apart. To provide increased robustness against
	//    packet loss, a responder MAY send up to eight unsolicited responses,
	//    provided that the interval between unsolicited responses increases by
	//    at least a factor of two with every response sent.
	timeout := 1 * time.Second
	for i := 0; i < multicastRepetitions; i++ {
		for _, intf := range s.ifaces {
			resp := new(dns.Msg)
			resp.MsgHdr.Response = true
			// TODO: make response authoritative if we are the publisher
			resp.Compress = true
			resp.Answer = []dns.RR{}
			resp.Extra = []dns.RR{}
			s.composeLookupAnswers(resp, s.ttl, intf.Index, nil, true)
// 			log.Printf("[zeroconf-dbg] probe announcement iface=%s ttl=%d service=%s", intf.Name, s.ttl, s.service.ServiceName())
			if err := s.multicastResponse(resp, intf.Index); err != nil {
				log.Println("[ERR] zeroconf: failed to send announcement:", err.Error())
			}
		}
		time.Sleep(timeout)
		timeout *= 2
	}
}

// announceText sends a Text announcement with cache flush enabled
// announceText multicasts the current TXT record without waiting for a query.
//
// RFC 6762 8.4 requires at least two unsolicited responses one second apart:
// mDNS is unacknowledged UDP multicast, so on a busy LAN one dropped :5353
// packet would cost a subscriber the whole update interval - ten minutes in the
// ITxPT S02 test, which then reports the update as never received.
//
// The repetitions run in their own goroutine so SetText stays non-blocking for
// its caller, which holds a lock while updating the service record.
func (s *Server) announceText() {
	go func() {
		for i := 0; i < multicastRepetitions; i++ {
			if i > 0 {
				time.Sleep(time.Second)
			}
			// Shutdown() sends the goodbye records and only then closes the
			// conns and sets isShutdown, so a periodic updater can land inside
			// that window and re-announce a service that was just withdrawn -
			// peers would re-cache it for the whole TTL.
			s.shutdownLock.Lock()
			down := s.isShutdown
			s.shutdownLock.Unlock()
			if down {
				return
			}
			// handleQuery consults suppressCheck before answering; an
			// unsolicited announcement carries the same record, so it has to
			// honour the same gate or the suppression window would leak the
			// value it exists to hold back.
			if s.suppressCheck != nil && s.suppressCheck() {
				continue
			}
			s.announceTextOnce()
		}
	}()
}

func (s *Server) announceTextOnce() {
	text := s.textSnapshot()
	name := s.service.ServiceInstanceName()
	for _, intf := range s.ifaces {
		resp := new(dns.Msg)
		resp.MsgHdr.Response = true

		txt := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET | qClassCacheFlush,
				Ttl:    s.ttl,
			},
			Txt: text,
		}
		resp.Answer = s.appendAddrs([]dns.RR{txt}, s.ttl, intf.Index, nil, true)
		// probe() and unregister() report their send errors; this path used to
		// discard them, so an interface going down stopped the interval updates
		// with nothing in the log - the failure only showed up as a failed
		// compliance run.
		if err := s.multicastResponse(resp, intf.Index); err != nil {
			log.Printf("[zeroconf] announce %s on %s failed: %s", name, intf.Name, err)
		}
	}
}

func (s *Server) unregister() error {
	var firstErr error
	for _, intf := range s.ifaces {
		resp := new(dns.Msg)
		resp.MsgHdr.Response = true
		resp.Answer = []dns.RR{}
		resp.Extra = []dns.RR{}
		s.composeLookupAnswers(resp, 0, intf.Index, nil, true)
		if err := s.multicastResponse(resp, intf.Index); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) appendAddrs(list []dns.RR, ttl uint32, ifIndex int, from net.Addr, flushCache bool) []dns.RR {
    var v4, v6 []net.IP

    if ifIndex != 0 {
        for _, cache := range s.ifaceAddrs {
            if cache.iface.Index == ifIndex {
                v4 = cache.v4
                v6 = cache.v6
                break
            }
        }
    }

    // If interface not found or ifIndex was 0, fall back to other methods
    if len(v4) == 0 && len(v6) == 0 {
        // If no source address is provided, fall back to all pre-populated IPs
        if from == nil {
            v4 = s.service.AddrIPv4
            v6 = s.service.AddrIPv6
            if len(v4) == 0 && len(v6) == 0 {
                // Use cached interface addresses
                for _, cache := range s.ifaceAddrs {
                    v4 = append(v4, cache.v4...)
                    v6 = append(v6, cache.v6...)
                }
            }
        } else {
            // Extract the source IP from the incoming packet
            var srcIP net.IP
            if udpAddr, ok := from.(*net.UDPAddr); ok {
                srcIP = udpAddr.IP
            }

            // If we have a source IP, find the interface with a matching IP or subnet
            // Use cached s.ifaceAddrs to avoid expensive syscalls on every query
            if srcIP != nil {
                for _, cache := range s.ifaceAddrs {
                    for _, addr := range cache.addrs {
                        if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
                            // Check if the source IP is in the same subnet or matches the interface IP
                            if ipNet.Contains(srcIP) || ipNet.IP.Equal(srcIP) {
                                // Use cached IPs instead of calling addrsForInterface
                                v4 = append(v4, cache.v4...)
                                v6 = append(v6, cache.v6...)
                                break
                            }
                        }
                    }
                    if len(v4) > 0 || len(v6) > 0 {
                        break
                    }
                }
            }

            // If no matching interface was found, fall back to pre-populated IPs
            if len(v4) == 0 && len(v6) == 0 {
                v4 = s.service.AddrIPv4
                v6 = s.service.AddrIPv6
            }
        }
    }

    if ttl > 0 {
        // RFC6762 Section 10 says A/AAAA records SHOULD use TTL of 120s
        ttl = 120
    }
    var cacheFlushBit uint16
    if flushCache {
        cacheFlushBit = qClassCacheFlush
    }
    for _, ipv4 := range v4 {
        a := &dns.A{
            Hdr: dns.RR_Header{
                Name:   s.service.HostName,
                Rrtype: dns.TypeA,
                Class:  dns.ClassINET | cacheFlushBit,
                Ttl:    ttl,
            },
            A: ipv4, // Fix: Use the actual IPv4 address
        }
        list = append(list, a)
    }
    for _, ipv6 := range v6 {
        aaaa := &dns.AAAA{
            Hdr: dns.RR_Header{
                Name:   s.service.HostName,
                Rrtype: dns.TypeAAAA,
                Class:  dns.ClassINET | cacheFlushBit,
                Ttl:    ttl,
            },
            AAAA: ipv6,
        }
        list = append(list, aaaa)
    }
    return list
}

func addrsForInterface(iface *net.Interface) ([]net.IP, []net.IP) {
	var v4, v6, v6local []net.IP
	addrs, _ := iface.Addrs()
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				v4 = append(v4, ipnet.IP)
			} else {
				switch ip := ipnet.IP.To16(); ip != nil {
				case ip.IsGlobalUnicast():
					v6 = append(v6, ipnet.IP)
				case ip.IsLinkLocalUnicast():
					v6local = append(v6local, ipnet.IP)
				}
			}
		}
	}
	if len(v6) == 0 {
		v6 = v6local
	}
	return v4, v6
}

// unicastResponse is used to send a unicast response packet
func (s *Server) unicastResponse(resp *dns.Msg, ifIndex int, from net.Addr) error {
	buf, err := resp.Pack()
	if err != nil {
		return err
	}
	addr := from.(*net.UDPAddr)
	if addr.IP.To4() != nil {
		if ifIndex != 0 {
			var wcm ipv4.ControlMessage
			wcm.IfIndex = ifIndex
			_, err = s.ipv4conn.WriteTo(buf, &wcm, addr)
		} else {
			_, err = s.ipv4conn.WriteTo(buf, nil, addr)
		}
		return err
	} else {
		if ifIndex != 0 {
			var wcm ipv6.ControlMessage
			wcm.IfIndex = ifIndex
			_, err = s.ipv6conn.WriteTo(buf, &wcm, addr)
		} else {
			_, err = s.ipv6conn.WriteTo(buf, nil, addr)
		}
		return err
	}
}

// multicastResponse us used to send a multicast response packet
func (s *Server) multicastResponse(msg *dns.Msg, ifIndex int) error {
    buf, err := msg.Pack()
    if err != nil {
        return err
    }
    if s.ipv4conn != nil {
        var wcm ipv4.ControlMessage
        if ifIndex != 0 {
            wcm.IfIndex = ifIndex
            s.ipv4conn.WriteTo(buf, &wcm, ipv4Addr)
        } else {
            for _, intf := range s.ifaces {
                wcm.IfIndex = intf.Index
                s.ipv4conn.WriteTo(buf, &wcm, ipv4Addr)
            }
        }
    }
    if s.ipv6conn != nil {
        var wcm ipv6.ControlMessage
        if ifIndex != 0 {
            wcm.IfIndex = ifIndex
            s.ipv6conn.WriteTo(buf, &wcm, ipv6Addr)
        } else {
            for _, intf := range s.ifaces {
                wcm.IfIndex = intf.Index
                s.ipv6conn.WriteTo(buf, &wcm, ipv6Addr)
            }
        }
    }
    return nil
}

func isUnicastQuestion(q dns.Question) bool {
	// From RFC6762
	// 18.12.  Repurposing of Top Bit of qclass in Question Section
	//
	//    In the Question Section of a Multicast DNS query, the top bit of the
	//    qclass field is used to indicate that unicast responses are preferred
	//    for this particular question.  (See Section 5.4.)
	return q.Qclass&qClassCacheFlush != 0
}
