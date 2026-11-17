package hopping

import (
    "log"
    "math/rand"
    "net"
    "net/netip"
    "strconv"
    "sync"
    "sync/atomic"
    "time"

    "github.com/daeuniverse/outbound/netproxy"
)

// Controller picks destination ports over time.
type Controller struct {
    host   string
    ports  []int
    cur    atomic.Int32
    stopCh chan struct{}
    once   sync.Once
}

func NewController(host string, ports []int, startPort int) *Controller {
    c := &Controller{
        host:   host,
        ports:  append([]int(nil), ports...),
        stopCh: make(chan struct{}),
    }
    idx := 0
    if startPort > 0 {
        for i, p := range c.ports {
            if p == startPort {
                idx = i
                break
            }
        }
    }
    c.cur.Store(int32(idx))
    return c
}

func (c *Controller) Ports() []int {
    return append([]int(nil), c.ports...)
}

func (c *Controller) CurrentPort() int {
    i := int(c.cur.Load())
    if i < 0 || i >= len(c.ports) {
        i = 0
    }
    return c.ports[i]
}

func (c *Controller) CurrentAddr() string {
    return net.JoinHostPort(c.host, strconv.Itoa(c.CurrentPort()))
}

func (c *Controller) CurrentUDPAddr() *net.UDPAddr {
    addr, err := net.ResolveUDPAddr("udp", c.CurrentAddr())
    if err != nil {
        // Keep host if possible; fall back to port only when resolve fails hard.
        return &net.UDPAddr{IP: net.ParseIP(c.host), Port: c.CurrentPort()}
    }
    return addr
}

func (c *Controller) Hop() string {
    if len(c.ports) <= 1 {
        return c.CurrentAddr()
    }
    old := int(c.cur.Load())
    if old < 0 || old >= len(c.ports) {
        old = 0
    }
    n := len(c.ports)
    // Prefer a different port when possible.
    next := rand.Intn(n)
    if n > 1 && next == old {
        next = (next + 1) % n
    }
    c.cur.Store(int32(next))
    addr := c.CurrentAddr()
    log.Printf("juicity hop: %s:%d -> %s", c.host, c.ports[old], addr)
    return addr
}

// Start launches periodic hopping. No-op if interval<=0 or single port.
func (c *Controller) Start(interval time.Duration) {
    if interval <= 0 || len(c.ports) <= 1 {
        return
    }
    c.once.Do(func() {
        log.Printf("juicity hop: start host=%s ports=%v interval=%s current=%s",
            c.host, c.ports, interval, c.CurrentAddr())
        go func() {
            t := time.NewTicker(interval)
            defer t.Stop()
            for {
                select {
                case <-t.C:
                    c.Hop()
                case <-c.stopCh:
                    return
                }
            }
        }()
    })
}

func (c *Controller) Stop() {
    select {
    case <-c.stopCh:
    default:
        close(c.stopCh)
    }
}

// PacketConn rewrites outbound destinations to the controller's current port.
// Inbound packets are unchanged. Same local socket => smooth path change with server DNAT.
type PacketConn struct {
    inner netproxy.PacketConn
    ctrl  *Controller
}

func Wrap(inner netproxy.PacketConn, ctrl *Controller) netproxy.PacketConn {
    if ctrl == nil || len(ctrl.ports) <= 1 {
        return inner
    }
    log.Printf("juicity hop: PacketConn wrapped, initial dest=%s", ctrl.CurrentAddr())
    return &PacketConn{inner: inner, ctrl: ctrl}
}

func (p *PacketConn) Read(b []byte) (n int, err error) {
    return p.inner.Read(b)
}

func (p *PacketConn) Write(b []byte) (n int, err error) {
    // Force current hop destination.
    return p.inner.WriteTo(b, p.ctrl.CurrentAddr())
}

func (p *PacketConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
    return p.inner.ReadFrom(b)
}

func (p *PacketConn) WriteTo(b []byte, _ string) (n int, err error) {
    // Ignore quic-go's peer addr; always send to current hop port.
    return p.inner.WriteTo(b, p.ctrl.CurrentAddr())
}

func (p *PacketConn) Close() error {
    return p.inner.Close()
}

func (p *PacketConn) SetDeadline(t time.Time) error {
    return p.inner.SetDeadline(t)
}

func (p *PacketConn) SetReadDeadline(t time.Time) error {
    return p.inner.SetReadDeadline(t)
}

func (p *PacketConn) SetWriteDeadline(t time.Time) error {
    return p.inner.SetWriteDeadline(t)
}

// Optional buffer helpers for FakeNetPacketConn / quic OOB path.
func (p *PacketConn) SetWriteBuffer(size int) error {
    if c, ok := p.inner.(interface{ SetWriteBuffer(int) error }); ok {
        return c.SetWriteBuffer(size)
    }
    return nil
}

func (p *PacketConn) SetReadBuffer(size int) error {
    if c, ok := p.inner.(interface{ SetReadBuffer(int) error }); ok {
        return c.SetReadBuffer(size)
    }
    return nil
}
