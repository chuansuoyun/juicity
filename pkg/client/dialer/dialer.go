package dialer

import (
	"context"
	"runtime"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/juicity/juicity/config"
	"github.com/juicity/juicity/pkg/client/hopping"
)

var protectPath string

type clientDialer struct {
	Dialer netproxy.Dialer
	conf   *config.Config
	hop    *hopping.Controller
}

func NewClientDialer(conf *config.Config, hop *hopping.Controller) *clientDialer {
	return &clientDialer{
		Dialer: direct.SymmetricDirect,
		conf:   conf,
		hop:    hop,
	}
}

// DialContext implements netproxy.Dialer.
func (c *clientDialer) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	// When hopping, dial the *current* hop address so the first path is valid,
	// then wrap writes so later hops only change destination port.
	dialAddr := addr
	if c.hop != nil {
		dialAddr = c.hop.CurrentAddr()
	}

	var (
		conn netproxy.Conn
		err  error
	)
	if runtime.GOOS == "android" || runtime.GOOS == "linux" {
		protectPath = c.conf.ProtectPath
		if protectPath != "" {
			magicNetwork := netproxy.MagicNetwork{
				Network: "udp",
				Mark:    114514,
			}
			conn, err = c.Dialer.DialContext(ctx, magicNetwork.Encode(), dialAddr)
		} else {
			conn, err = c.Dialer.DialContext(ctx, network, dialAddr)
		}
	} else {
		conn, err = c.Dialer.DialContext(ctx, network, dialAddr)
	}
	if err != nil {
		return nil, err
	}
	if c.hop != nil {
		if pc, ok := conn.(netproxy.PacketConn); ok {
			return hopping.Wrap(pc, c.hop).(netproxy.Conn), nil
		}
	}
	return conn, nil
}

var _ netproxy.Dialer = (*clientDialer)(nil)
