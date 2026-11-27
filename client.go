package zeroconf

import (
	"context"
	"fmt"
	"net"
	"sync"
	"strings"
	"time"

	"github.com/Intrising/backoff"
	"github.com/Intrising/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IPType specifies the IP traffic the client listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, often contain
// both DNS A and AAAA entries.
type IPType uint8

// Options for IPType.
const (
	IPv4        = 0x01
	IPv6        = 0x02
	IPv4AndIPv6 = (IPv4 | IPv6) //< Default option.
)

type clientOpts struct {
	listenOn IPType
	ifaces   []net.Interface
}

// ClientOption fills the option struct to configure intefaces, etc.
type ClientOption func(*clientOpts)

// SelectIPTraffic selects the type of IP packets (IPv4, IPv6, or both) this
// instance listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, may contain
// both DNS A and AAAA entries.
func SelectIPTraffic(t IPType) ClientOption {
	return func(o *clientOpts) {
		o.listenOn = t
	}
}

// SelectIfaces selects the interfaces to query for mDNS records
func SelectIfaces(ifaces []net.Interface) ClientOption {
	return func(o *clientOpts) {
		o.ifaces = ifaces
	}
}

// Resolver acts as entry point for service lookups and to browse the DNS-SD.
type Resolver struct {
	c *client
}

// NewResolver creates a new resolver and joins the UDP multicast groups to
// listen for mDNS messages.
func NewResolver(options ...ClientOption) (*Resolver, error) {
	// Apply default configuration and load supplied options.
	var conf = clientOpts{
		listenOn: IPv4AndIPv6,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}

	c, err := newClient(conf)
	if err != nil {
		return nil, err
	}
	return &Resolver{
		c: c,
	}, nil
}

// Browse for all services of a given type in a given domain.
func (r *Resolver) Browse(ctx context.Context, service, domain string, entries chan<- *ServiceEntry) error {
	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	params.isBrowsing = true
	return r.c.start(ctx, params, r.c.periodicQuery)
}

// Watch keeps a browse of a service open for as long as ctx lives.
//
// Unlike Browse it reports an instance every time an answer for it arrives,
// not only the first time, so the subscriber can refresh the lifetime,
// addresses and SRV priority/weight it holds. Each report is the merged view
// of the instance: a field or address family that the latest packet did not
// carry keeps its last known value, and an address that was withdrawn (TTL 0)
// is left out. A goodbye (PTR or SRV record with TTL 0) for an instance that
// has been reported is delivered as an event with Removed set. Reports and
// goodbyes share the one events channel, so the subscriber sees them in the
// order the packets were received.
//
// The query is repeated every interval without ever giving up (Browse backs
// off and stops). kick may be nil; a value received on it sends the query at
// once, for a subscriber that knows the network has just changed.
//
// events is closed when the watch ends: when ctx is done, when no interface
// accepts the query any more, or when every receive socket has failed.
func (r *Resolver) Watch(ctx context.Context, service, domain string, interval time.Duration, kick <-chan struct{}, events chan<- WatchEvent) error {
	if interval <= 0 {
		return fmt.Errorf("zeroconf: watch interval must be positive")
	}
	if events == nil {
		return fmt.Errorf("zeroconf: watch needs an events channel")
	}
	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.isBrowsing = true
	params.watch = true
	params.events = events
	params.queryInterval = interval
	params.kick = kick
	return r.c.start(ctx, params, r.c.watchQuery)
}

// Lookup a specific service by its name and type in a given domain.
func (r *Resolver) Lookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry) error {
	params := defaultParams(service)
	params.Instance = instance
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	return r.c.start(ctx, params, r.c.periodicQuery)
}

// defaultParams returns a default set of QueryParams.
func defaultParams(service string) *lookupParams {
	return newLookupParams("", service, "local", false, make(chan *ServiceEntry))
}

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	ipv4conn *ipv4.PacketConn
	ipv6conn *ipv6.PacketConn
	ifaces   []net.Interface
	recvWg   sync.WaitGroup
}

// Client structure constructor
func newClient(opts clientOpts) (*client, error) {
	ifaces := opts.ifaces
	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}
	// IPv4 interfaces
	var ipv4conn *ipv4.PacketConn
	if (opts.listenOn & IPv4) > 0 {
		var err error
		ipv4conn, err = joinUdp4Multicast(ifaces)
		if err != nil {
			return nil, err
		}
	}
	// IPv6 interfaces
	var ipv6conn *ipv6.PacketConn
	if (opts.listenOn & IPv6) > 0 {
		var err error
		ipv6conn, err = joinUdp6Multicast(ifaces)
		if err != nil {
			return nil, err
		}
	}

	return &client{
		ipv4conn: ipv4conn,
		ipv6conn: ipv6conn,
		ifaces:   ifaces,
	}, nil
}

// start launches the receive loop, sends the first query and then runs
// queryLoop, which repeats the query. The first query failing, queryLoop
// returning an error and the receive loop running out of sockets all cancel
// the derived context, which ends the receive loop, the query loop and closes
// the entries channel.
func (c *client) start(ctx context.Context, params *lookupParams, queryLoop func(context.Context, *lookupParams) error) error {
	ctx, cancel := context.WithCancel(ctx)
	go c.mainloop(ctx, cancel, params)

	if err := c.query(params); err != nil {
		cancel()
		return err
	}
	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	go func() {
		if err := queryLoop(ctx, params); err != nil {
			cancel()
		}
	}()

	return nil
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context, cancel context.CancelFunc, params *lookupParams) {
	// start listening for responses
	msgCh := make(chan *dns.Msg, 32)
	// A receiver reports here when it stops. Once none is left the loop can
	// no longer learn anything, so it ends and closes the entries channel
	// instead of leaving the subscriber waiting on a dead socket.
	recvExit := make(chan struct{}, 2)
	receivers := 0
	if c.ipv4conn != nil {
		receivers++
		c.recvWg.Add(1)
		go func() {
			defer c.recvWg.Done()
			c.recv(ctx, c.ipv4conn, msgCh)
			recvExit <- struct{}{}
		}()
	}
	if c.ipv6conn != nil {
		receivers++
		c.recvWg.Add(1)
		go func() {
			defer c.recvWg.Done()
			c.recv(ctx, c.ipv6conn, msgCh)
			recvExit <- struct{}{}
		}()
	}

	// Iterate through channels from listeners goroutines
	st := newBrowseState()
	for {
		select {
		case <-ctx.Done():
			// Context expired. Notify subscriber that we are done here.
			params.done()
			c.shutdown()
			return
		case <-recvExit:
			receivers--
			if receivers > 0 {
				continue
			}
			// Stop the query loop as well: it would go on writing to
			// sockets that are gone.
			cancel()
			params.done()
			c.shutdown()
			return
		case msg := <-msgCh:
			st.process(ctx, params, parseAnswers(msg, params), time.Now())
		}
	}
}

// answer is what one mDNS message says about one service instance.
type answer struct {
	entry *ServiceEntry
	// Which parts the message carried. A part that is absent keeps its last
	// known value in watch mode.
	hasSRV, hasTXT, hasA, hasAAAA bool
	// goodbye: the instance's PTR or SRV record came with TTL 0.
	goodbye bool
	// Addresses withdrawn by the message (A/AAAA record with TTL 0).
	goneIPv4, goneIPv6 []net.IP
}

// parseAnswers builds, per service instance, what one mDNS message carries.
//
// An entry's TTL is the TTL of its SRV record. PTR and TXT records of the same
// instance often carry a different (longer) TTL; they only set the entry's TTL
// when the message has no SRV record for it, so that a subscriber that expires
// instances by TTL does not keep one for the lifetime of its TXT record.
func parseAnswers(msg *dns.Msg, params *lookupParams) map[string]*answer {
	answers := make(map[string]*answer)
	get := func(key, instance string) *answer {
		a, ok := answers[key]
		if !ok {
			a = &answer{entry: NewServiceEntry(instance, params.Service, params.Domain)}
			answers[key] = a
		}
		return a
	}
	sections := append(msg.Answer, msg.Ns...)
	sections = append(sections, msg.Extra...)

	for _, rec := range sections {
		switch rr := rec.(type) {
		case *dns.PTR:
			if params.ServiceName() != rr.Hdr.Name {
				continue
			}
			if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Ptr {
				continue
			}
			a := get(rr.Ptr, trimDot(strings.Replace(rr.Ptr, rr.Hdr.Name, "", -1)))
			if rr.Hdr.Ttl == 0 {
				a.goodbye = true
			}
			if !a.hasSRV {
				a.entry.TTL = rr.Hdr.Ttl
			}
		case *dns.SRV:
			if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
				continue
			} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
				continue
			}
			a := get(rr.Hdr.Name, trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)))
			a.entry.HostName = rr.Target
			a.entry.Port = int(rr.Port)
			a.entry.Priority = rr.Priority
			a.entry.Weight = rr.Weight
			a.entry.TTL = rr.Hdr.Ttl
			a.hasSRV = true
			if rr.Hdr.Ttl == 0 {
				a.goodbye = true
			}
		case *dns.TXT:
			if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
				continue
			} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
				continue
			}
			a := get(rr.Hdr.Name, trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)))
			a.entry.Text = rr.Txt
			a.hasTXT = true
			if !a.hasSRV {
				a.entry.TTL = rr.Hdr.Ttl
			}
		}
	}
	// Associate IPs in a second round as other fields should be filled by now.
	// An address record with TTL 0 withdraws the address: it is not added.
	for _, rec := range sections {
		switch rr := rec.(type) {
		case *dns.A:
			for _, a := range answers {
				if a.entry.HostName != rr.Hdr.Name {
					continue
				}
				if rr.Hdr.Ttl == 0 {
					a.goneIPv4 = append(a.goneIPv4, rr.A)
					continue
				}
				a.entry.AddrIPv4 = append(a.entry.AddrIPv4, rr.A)
				a.hasA = true
			}
		case *dns.AAAA:
			for _, a := range answers {
				if a.entry.HostName != rr.Hdr.Name {
					continue
				}
				if rr.Hdr.Ttl == 0 {
					a.goneIPv6 = append(a.goneIPv6, rr.AAAA)
					continue
				}
				a.entry.AddrIPv6 = append(a.entry.AddrIPv6, rr.AAAA)
				a.hasAAAA = true
			}
		}
	}
	return answers
}

// browseState is what the receive loop remembers between messages: the
// instances it knows (reported ones, and in watch mode also those still
// waiting for an address) and, in watch mode, when each was last heard.
type browseState struct {
	known     map[string]*ServiceEntry
	reported  map[string]bool
	heard     map[string]time.Time
	lastPurge time.Time
}

func newBrowseState() *browseState {
	return &browseState{
		known:    make(map[string]*ServiceEntry),
		reported: make(map[string]bool),
		heard:    make(map[string]time.Time),
	}
}

func (st *browseState) forget(key string) {
	delete(st.known, key)
	delete(st.reported, key)
	delete(st.heard, key)
}

// process hands the content of one message to the subscriber.
func (st *browseState) process(ctx context.Context, params *lookupParams, answers map[string]*answer, now time.Time) {
	for key, a := range answers {
		e := a.entry
		if a.goodbye || e.TTL == 0 {
			// Report a goodbye only for an instance the subscriber has been
			// told about; repeated goodbyes (both sockets, the server's own
			// repetitions) find it already forgotten.
			wasReported := st.reported[key]
			st.forget(key)
			if wasReported && params.watch {
				// Never block the receive loop on a subscriber that has gone
				// away with the context.
				select {
				case params.events <- WatchEvent{Entry: e, Removed: true}:
				case <-ctx.Done():
				}
			}
			continue
		}
		if params.watch {
			e = mergeEntry(st.known[key], a)
			st.known[key] = e
			st.heard[key] = now
		} else if st.reported[key] {
			continue
		}

		// If this is an DNS-SD query do not throw PTR away.
		// It is expected to have only PTR for enumeration
		if params.ServiceRecord.ServiceTypeName() != params.ServiceRecord.ServiceName() {
			// Require at least one resolved IP address for ServiceEntry
			// TODO: wait some more time as chances are high both will arrive.
			if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
				continue
			}
		}
		// Submit entry to subscriber and cache it.
		// This is also a point to possibly stop probing actively for a
		// service entry. The send gives up when the context ends, so a
		// subscriber that stopped reading cannot hold the loop forever.
		if params.watch {
			// The subscriber gets its own copy, not the cached entry.
			select {
			case params.events <- WatchEvent{Entry: copyEntry(e)}:
			case <-ctx.Done():
			}
		} else {
			select {
			case params.Entries <- e:
			case <-ctx.Done():
			}
			st.known[key] = e
		}
		st.reported[key] = true
		if !params.isBrowsing {
			params.disableProbing()
		}
	}
	if params.watch {
		st.purge(params, now)
	}
}

// purge forgets, in watch mode, the instances that have not been heard for
// longer than their TTL, so the state does not grow with every instance name
// ever seen on a network where services come and go without a goodbye. It is
// silent: expiry is the subscriber's own business; Removed events are for
// goodbyes.
func (st *browseState) purge(params *lookupParams, now time.Time) {
	if now.Sub(st.lastPurge) < params.queryInterval {
		return
	}
	st.lastPurge = now
	for key, e := range st.known {
		ttl := time.Duration(e.TTL) * time.Second
		if ttl < 2*params.queryInterval {
			ttl = 2 * params.queryInterval
		}
		if now.Sub(st.heard[key]) > ttl {
			st.forget(key)
		}
	}
}

// mergeEntry returns the merged view of an instance: what the latest message
// carried, completed with the last known value of every part it did not carry.
// Withdrawn addresses are removed. prev is not modified.
func mergeEntry(prev *ServiceEntry, a *answer) *ServiceEntry {
	out := copyEntry(a.entry)
	if prev == nil {
		return out
	}
	if !a.hasSRV {
		out.HostName = prev.HostName
		out.Port = prev.Port
		out.Priority = prev.Priority
		out.Weight = prev.Weight
		if prev.HostName != "" {
			out.TTL = prev.TTL // keep the SRV TTL
		}
	}
	if !a.hasTXT {
		out.Text = append([]string(nil), prev.Text...)
	}
	if !a.hasA {
		out.AddrIPv4 = withoutIPs(prev.AddrIPv4, a.goneIPv4)
	}
	if !a.hasAAAA {
		out.AddrIPv6 = withoutIPs(prev.AddrIPv6, a.goneIPv6)
	}
	return out
}

func copyEntry(e *ServiceEntry) *ServiceEntry {
	out := *e
	out.Text = append([]string(nil), e.Text...)
	out.AddrIPv4 = append([]net.IP(nil), e.AddrIPv4...)
	out.AddrIPv6 = append([]net.IP(nil), e.AddrIPv6...)
	return &out
}

// withoutIPs returns a copy of ips without the addresses in gone.
func withoutIPs(ips, gone []net.IP) []net.IP {
	var out []net.IP
	for _, ip := range ips {
		keep := true
		for _, g := range gone {
			if ip.Equal(g) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, ip)
		}
	}
	return out
}

// Shutdown client will close currently open connections and channel implicitly.
func (c *client) shutdown() {
	if c.ipv4conn != nil {
		c.ipv4conn.SetReadDeadline(time.Now())
		c.ipv4conn.Close()
	}
	if c.ipv6conn != nil {
		c.ipv6conn.SetReadDeadline(time.Now())
		c.ipv6conn.Close()
	}
	c.recvWg.Wait()
}

// Data receiving routine reads from connection, unpacks packets into dns.Msg
// structures and sends them to a given msgCh channel
func (c *client) recv(ctx context.Context, l interface{}, msgCh chan *dns.Msg) {
	var readFrom func([]byte) (n int, src net.Addr, err error)

	switch pConn := l.(type) {
	case *ipv6.PacketConn:
		readFrom = func(b []byte) (n int, src net.Addr, err error) {
			n, _, src, err = pConn.ReadFrom(b)
			return
		}
	case *ipv4.PacketConn:
		readFrom = func(b []byte) (n int, src net.Addr, err error) {
			n, _, src, err = pConn.ReadFrom(b)
			return
		}

	default:
		return
	}

	buf := make([]byte, 65536)
	var fatalErr error
	for {
		// Handles the following cases:
		// - ReadFrom aborts with error due to closed UDP connection -> causes ctx cancel
		// - ReadFrom aborts otherwise.
		// TODO: the context check can be removed. Verify!
		if ctx.Err() != nil || fatalErr != nil {
			return
		}

		n, _, err := readFrom(buf)
		if err != nil {
			fatalErr = err
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			// log.Printf("[WARN] mdns: Failed to unpack packet: %v", err)
			continue
		}
		select {
		case msgCh <- msg:
			// Submit decoded DNS message and continue.
		case <-ctx.Done():
			// Abort.
			return
		}
	}
}

// periodicQuery sens multiple probes until a valid response is received by
// the main processing loop or some timeout/cancel fires.
// TODO: move error reporting to shutdown function as periodicQuery is called from
// go routine context.
func (c *client) periodicQuery(ctx context.Context, params *lookupParams) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 4 * time.Second
	bo.MaxInterval = 60 * time.Second
	bo.Reset()

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		// Backoff and cancel logic.
		wait := bo.NextBackOff()
		if wait == backoff.Stop {
			return fmt.Errorf("periodicQuery: abort due to timeout")
		}
		if timer == nil {
			timer = time.NewTimer(wait)
		} else {
			timer.Reset(wait)
		}
		select {
		case <-timer.C:
			// Wait for next iteration.
		case <-params.stopProbing:
			// Chan is closed (or happened in the past).
			// Done here. Received a matching mDNS entry.
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
		// Do periodic query.
		if err := c.query(params); err != nil {
			return err
		}
	}
}

// watchQuery repeats the query every params.queryInterval, and at once when
// params.kick fires, until ctx is done. It returns an error when no interface
// accepts the query any more; the caller then ends the watch.
func (c *client) watchQuery(ctx context.Context, params *lookupParams) error {
	ticker := time.NewTicker(params.queryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-params.kick: // a nil channel never fires
		case <-ctx.Done():
			return nil
		}
		if err := c.query(params); err != nil {
			return err
		}
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
// start response listeners goroutines and loops over the entries channel.
func (c *client) query(params *lookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// send the query
	m := new(dns.Msg)
	if params.Instance != "" { // service instance name lookup
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
		m.Question = []dns.Question{
			{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
			{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		}
	} else if len(params.Subtypes) > 0 { // service subtype browse
		m.SetQuestion(params.Subtypes[0], dns.TypePTR)
	} else { // service name browse
		m.SetQuestion(serviceName, dns.TypePTR)
	}
	m.RecursionDesired = false
	sent, err := c.sendQuery(m)
	if err != nil {
		return err
	}
	// A watch has to notice that it has gone deaf and mute: when no interface
	// accepts the query any more it ends, so the subscriber can open a new one.
	// Browse and Lookup keep ignoring send errors, as before.
	if params.watch && sent == 0 {
		return fmt.Errorf("zeroconf: no interface accepted the query")
	}

	return nil
}

// Pack the dns.Msg and write to available connections (multicast). It returns
// the number of writes that succeeded; an individual write error is not an
// error of sendQuery (an interface may be down while others work).
func (c *client) sendQuery(msg *dns.Msg) (int, error) {
	buf, err := msg.Pack()
	if err != nil {
		return 0, err
	}
	sent := 0
	if c.ipv4conn != nil {
		var wcm ipv4.ControlMessage
		for ifi := range c.ifaces {
			wcm.IfIndex = c.ifaces[ifi].Index
			if _, err := c.ipv4conn.WriteTo(buf, &wcm, ipv4Addr); err == nil {
				sent++
			}
		}
	}
	if c.ipv6conn != nil {
		var wcm ipv6.ControlMessage
		for ifi := range c.ifaces {
			wcm.IfIndex = c.ifaces[ifi].Index
			if _, err := c.ipv6conn.WriteTo(buf, &wcm, ipv6Addr); err == nil {
				sent++
			}
		}
	}
	return sent, nil
}
