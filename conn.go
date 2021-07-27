package mdns

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type SocketConn interface {
	Close() error
	WriteTo(b []byte) (n int, err error)
	ReadFrom(b []byte) (n int, src net.Addr, err error)
	GenerateDnsResourceBody(ip net.IP) dnsmessage.ResourceBody
}

type SocketConn4 struct {
	socket        *ipv4.PacketConn
	broadcastAddr *net.UDPAddr
}

func NewSocketConn4(conn *ipv4.PacketConn) (conn4 *SocketConn4, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	joinErrCount := 0
	ipa := net.ParseIP(broadcastAddress4)
	for i := range ifaces {
		if err = conn.JoinGroup(&ifaces[i], &net.UDPAddr{IP: ipa}); err != nil {
			joinErrCount++
		}
	}

	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	broadcastAddr, err := net.ResolveUDPAddr("udp", broadcastAddress4+":"+broadcastPort)
	if err != nil {
		return nil, err
	}

	conn4 = &SocketConn4{
		socket:        conn,
		broadcastAddr: broadcastAddr,
	}
	return conn4, nil
}

func (conn4 *SocketConn4) GenerateDnsResourceBody(ip net.IP) dnsmessage.ResourceBody {
	rawIP := ip.To4()
	if rawIP == nil {
		return nil
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	var out [4]byte
	copy(out[:], ipInt.Bytes())

	return &dnsmessage.AResource{
		A: out,
	}
}

func (conn4 *SocketConn4) WriteTo(b []byte) (n int, err error) {
	return conn4.socket.WriteTo(b, nil, conn4.broadcastAddr)
}

func (conn4 *SocketConn4) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	n, _, src, err = conn4.socket.ReadFrom(b)
	return
}

func (conn4 *SocketConn4) Close() error {
	return conn4.socket.Close()
}

type SocketConn6 struct {
	socket        *ipv6.PacketConn
	broadcastAddr *net.UDPAddr
}

func NewSocketConn6(conn *ipv6.PacketConn) (conn6 *SocketConn6, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	joinErrCount := 0
	ipa := net.ParseIP(broadcastAddress6)
	for i := range ifaces {
		if err = conn.JoinGroup(&ifaces[i], &net.UDPAddr{IP: ipa}); err != nil {
			joinErrCount++
		}
	}

	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	broadcastAddr, err := net.ResolveUDPAddr("udp6", "["+broadcastAddress6+"]:"+broadcastPort)
	if err != nil {
		return nil, err
	}

	conn6 = &SocketConn6{
		socket:        conn,
		broadcastAddr: broadcastAddr,
	}
	return conn6, nil
}

func (conn6 *SocketConn6) GenerateDnsResourceBody(ip net.IP) (body dnsmessage.ResourceBody) {
	rawIP := ip.To16()
	if rawIP == nil {
		return
	}

	var out [16]byte
	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	copy(out[:], ipInt.Bytes())
	return &dnsmessage.AAAAResource{
		AAAA: out,
	}
}

func (conn6 *SocketConn6) WriteTo(b []byte) (n int, err error) {
	return conn6.socket.WriteTo(b, nil, conn6.broadcastAddr)
}

func (conn6 *SocketConn6) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	n, _, src, err = conn6.socket.ReadFrom(b)
	return
}

func (conn6 *SocketConn6) Close() error {
	return conn6.socket.Close()
}

// Conn represents a mDNS Server
type Conn struct {
	mu            sync.RWMutex
	log           logging.LeveledLogger
	socketConn    SocketConn
	queryInterval time.Duration
	localNames    []string
	queries       []query

	closed chan interface{}
}

type query struct {
	nameWithSuffix  string
	queryResultChan chan queryResult
}

type queryResult struct {
	answer dnsmessage.ResourceHeader
	addr   net.Addr
}

const (
	inboundBufferSize    = 512
	defaultQueryInterval = time.Second
	broadcastAddress4    = "224.0.0.251"
	broadcastAddress6    = "ff02::fb"
	broadcastPort        = "5353"
	maxMessageRecords    = 3
	responseTTL          = 120
)

// Server establishes a mDNS connection over an existing conn
func Server(conn *ipv4.PacketConn, config *Config) (*Conn, error) {
	socketConn, err := NewSocketConn4(conn)

	if err != nil {
		return nil, err
	}

	return doServe(socketConn, config)
}

func Server6(conn *ipv6.PacketConn, config *Config) (*Conn, error) {
	socketConn, err := NewSocketConn6(conn)

	if err != nil {
		return nil, err
	}

	return doServe(socketConn, config)
}

func doServe(socketConn SocketConn, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNilConfig
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	localNames := []string{}
	for _, l := range config.LocalNames {
		localNames = append(localNames, l+".")
	}

	c := &Conn{
		queryInterval: defaultQueryInterval,
		queries:       []query{},
		socketConn:    socketConn,
		localNames:    localNames,
		log:           loggerFactory.NewLogger("mdns"),
		closed:        make(chan interface{}),
	}
	if config.QueryInterval != 0 {
		c.queryInterval = config.QueryInterval
	}

	go c.start()
	return c, nil
}

// Close closes the mDNS Conn
func (c *Conn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
	}

	if err := c.socketConn.Close(); err != nil {
		return err
	}

	<-c.closed
	return nil
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, name string) (dnsmessage.ResourceHeader, net.Addr, error) {
	select {
	case <-c.closed:
		return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
	default:
	}

	nameWithSuffix := name + "."

	queryChan := make(chan queryResult, 1)
	c.mu.Lock()
	c.queries = append(c.queries, query{nameWithSuffix, queryChan})
	ticker := time.NewTicker(c.queryInterval)
	c.mu.Unlock()

	defer ticker.Stop()

	c.sendQuestion(nameWithSuffix)
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(nameWithSuffix)
		case <-c.closed:
			return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
		case res := <-queryChan:
			return res.answer, res.addr, nil
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, nil, errContextElapsed
		}
	}
}

func interfaceForRemote(remote string) (net.IP, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return nil, err
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if err := conn.Close(); err != nil {
		return nil, err
	}

	return localAddr.IP, nil
}

func (c *Conn) sendQuestion(name string) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{
			{
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
		},
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	if _, err := c.socketConn.WriteTo(rawQuery); err != nil {
		c.log.Warnf("Failed to send mDNS packet %v", err)
		return
	}
}

func (c *Conn) sendAnswer(name string, dst net.IP) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					Name:  packedName,
					TTL:   responseTTL,
				},
				Body: c.socketConn.GenerateDnsResourceBody(dst),
			},
		},
	}

	rawAnswer, err := msg.Pack()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	if _, err := c.socketConn.WriteTo(rawAnswer); err != nil {
		c.log.Warnf("Failed to send mDNS packet %v", err)
		return
	}
	fmt.Printf("answer sent: %s", name)
}

func (c *Conn) start() { //nolint gocognit
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		close(c.closed)
	}()

	b := make([]byte, inboundBufferSize)
	p := dnsmessage.Parser{}

	for {
		n, src, err := c.socketConn.ReadFrom(b)
		if err != nil {
			return
		}

		func() {
			c.mu.RLock()
			defer c.mu.RUnlock()

			if _, err := p.Start(b[:n]); err != nil {
				c.log.Warnf("Failed to parse mDNS packet %v", err)
				return
			}

			for i := 0; i <= maxMessageRecords; i++ {
				q, err := p.Question()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					break
				} else if err != nil {
					c.log.Warnf("Failed to parse mDNS packet %v", err)
					return
				}

				for _, localName := range c.localNames {
					if localName == q.Name.String() {
						localAddress, err := interfaceForRemote(src.String())
						if err != nil {
							c.log.Warnf("Failed to get local interface to communicate with %s: %v", src.String(), err)
							continue
						}

						c.sendAnswer(q.Name.String(), localAddress)
					}
				}
			}

			for i := 0; i <= maxMessageRecords; i++ {
				a, err := p.AnswerHeader()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					return
				}
				if err != nil {
					c.log.Warnf("Failed to parse mDNS packet %v", err)
					return
				}

				if a.Type != dnsmessage.TypeA && a.Type != dnsmessage.TypeAAAA {
					continue
				}

				for i := len(c.queries) - 1; i >= 0; i-- {
					if c.queries[i].nameWithSuffix == a.Name.String() {
						c.queries[i].queryResultChan <- queryResult{a, src}
						c.queries = append(c.queries[:i], c.queries[i+1:]...)
					}
				}
			}
		}()
	}
}
