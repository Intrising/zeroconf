package zeroconf

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ServiceRecord contains the basic description of a service, which contains instance name, service type & domain
type ServiceRecord struct {
	Instance string   `json:"name"`     // Instance name (e.g. "My web page")
	Service  string   `json:"type"`     // Service name (e.g. _http._tcp.)
	Subtypes []string `json:"subtypes"` // Service subtypes
	Domain   string   `json:"domain"`   // If blank, assumes "local"

	// private variable populated on ServiceRecord creation
	serviceName         string
	serviceInstanceName string
	serviceTypeName     string
}

// ServiceName returns a complete service name (e.g. _foobar._tcp.local.), which is composed
// of a service name (also referred as service type) and a domain.
func (s *ServiceRecord) ServiceName() string {
	return s.serviceName
}

// ServiceInstanceName returns a complete service instance name (e.g. MyDemo\ Service._foobar._tcp.local.),
// which is composed from service instance name, service name and a domain.
func (s *ServiceRecord) ServiceInstanceName() string {
	return s.serviceInstanceName
}

// ServiceTypeName returns the complete identifier for a DNS-SD query.
func (s *ServiceRecord) ServiceTypeName() string {
	return s.serviceTypeName
}

// NewServiceRecord constructs a ServiceRecord.
func NewServiceRecord(instance, service string, domain string) *ServiceRecord {
	service, subtypes := parseSubtypes(service)
	s := &ServiceRecord{
		Instance:    instance,
		Service:     service,
		Domain:      domain,
		serviceName: fmt.Sprintf("%s.%s.", trimDot(service), trimDot(domain)),
	}

	for _, subtype := range subtypes {
		s.Subtypes = append(s.Subtypes, fmt.Sprintf("%s._sub.%s", trimDot(subtype), s.serviceName))
	}

	// Cache service instance name
	if instance != "" {
		s.serviceInstanceName = fmt.Sprintf("%s.%s", trimDot(s.Instance), s.ServiceName())
	}

	// Cache service type name domain
	typeNameDomain := "local"
	if len(s.Domain) > 0 {
		typeNameDomain = trimDot(s.Domain)
	}
	s.serviceTypeName = fmt.Sprintf("_services._dns-sd._udp.%s.", typeNameDomain)

	return s
}

// lookupParams contains configurable properties to create a service discovery request
type lookupParams struct {
	ServiceRecord
	Entries chan<- *ServiceEntry // Entries Channel

	// Watch mode (Resolver.Watch): events replaces Entries. Every answer of
	// an instance and every goodbye is handed over as one WatchEvent, in the
	// order the packets were received. queryInterval is the fixed interval at
	// which the query is repeated for as long as the context lives; a value
	// received on kick sends the query at once.
	watch         bool
	events        chan<- WatchEvent
	queryInterval time.Duration
	kick          <-chan struct{}

	isBrowsing  bool
	stopProbing chan struct{}
	once        sync.Once
}

// newLookupParams constructs a lookupParams.
func newLookupParams(instance, service, domain string, isBrowsing bool, entries chan<- *ServiceEntry) *lookupParams {
	p := &lookupParams{
		ServiceRecord: *NewServiceRecord(instance, service, domain),
		Entries:       entries,
		isBrowsing:    isBrowsing,
	}
	if !isBrowsing {
		p.stopProbing = make(chan struct{})
	}
	return p
}

// Notify subscriber that no more entries will arrive. Mostly caused
// by an expired context.
func (l *lookupParams) done() {
	if l.watch {
		close(l.events)
		return
	}
	close(l.Entries)
}

func (l *lookupParams) disableProbing() {
	l.once.Do(func() { close(l.stopProbing) })
}

// ServiceEntry represents a browse/lookup result for client API.
// It is also used to configure service registration (server API), which is
// used to answer multicast queries.
type ServiceEntry struct {
	ServiceRecord
	HostName string   `json:"hostname"` // Host machine DNS name
	Port     int      `json:"port"`     // Service Port
	Priority uint16   `json:"priority"` // SRV priority: lower is more preferred
	Weight   uint16   `json:"weight"`   // SRV weight: higher is more preferred among equal priorities
	Text     []string `json:"text"`     // Service info served as a TXT record
	TTL      uint32   `json:"ttl"`      // TTL of the SRV record; of the PTR/TXT record when the answer carried no SRV
	AddrIPv4 []net.IP `json:"-"`        // Host machine IPv4 address
	AddrIPv6 []net.IP `json:"-"`        // Host machine IPv6 address
}

// WatchEvent is one change reported by Resolver.Watch.
type WatchEvent struct {
	// Entry is the merged view of the instance when Removed is false. When
	// Removed is true it only identifies the instance that said goodbye.
	Entry *ServiceEntry
	// Removed: a goodbye (PTR or SRV record with TTL 0) was received for an
	// instance that had been reported before.
	Removed bool
}

// NewServiceEntry constructs a ServiceEntry.
func NewServiceEntry(instance, service string, domain string) *ServiceEntry {
	return &ServiceEntry{
		ServiceRecord: *NewServiceRecord(instance, service, domain),
	}
}
