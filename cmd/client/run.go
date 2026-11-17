package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "net"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "syscall"
    "time"

    "github.com/daeuniverse/outbound/protocol"
    "github.com/daeuniverse/outbound/protocol/juicity"
    gliderLog "github.com/nadoo/glider/pkg/log"
    "github.com/sourcegraph/conc/pool"
    "github.com/spf13/cobra"

    "github.com/juicity/juicity/cmd/internal/shared"
    "github.com/juicity/juicity/common"
    "github.com/juicity/juicity/config"
    "github.com/juicity/juicity/pkg/client/dialer"
    "github.com/juicity/juicity/pkg/client/hopping"
    "github.com/juicity/juicity/pkg/log"
    "github.com/juicity/juicity/pkg/portlist"
    "github.com/juicity/juicity/server"
)

var (
    logger = log.NewLogger(&log.Options{
        TimeFormat: time.DateTime,
    })

    runCmd = &cobra.Command{
        Use:   "run",
        Short: "To run juicity-client in the foreground.",
        Run: func(cmd *cobra.Command, args []string) {
            if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
                os.Setenv("QUIC_GO_DISABLE_GSO", "1")
            }
            arguments := shared.GetArguments()
            conf, err := arguments.GetConfig()
            if err != nil {
                logger.Fatal().
                    Err(err).
                    Msg("Failed to read config")
            }

            if logger, err = arguments.GetLogger(conf.LogLevel); err != nil {
                logger.Fatal().
                    Err(err).
                    Msg("Failed to init logger")
            }
            gliderLog.SetLogger(logger)

            go func() {
                if err := Serve(conf); err != nil {
                    logger.Fatal().Err(err).Send()
                }
            }()
            sigs := make(chan os.Signal, 1)
            signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGILL)
            for sig := range sigs {
                logger.Warn().Str("signal", sig.String()).Msg("Exiting")
                return
            }
        },
    }
)

func Serve(conf *config.Config) error {
    // server may be "host", "host:port", or "[ipv6]:port"
    host, portStr, err := splitServer(conf.Server)
    if err != nil {
        return fmt.Errorf("parse server: %w", err)
    }

    // Prefer ports / server_ports (Windows uses "ports")
    portsSpec := conf.PortRange()
    var ports []int
    if portsSpec != "" {
        ports, err = portlist.Parse(portsSpec)
        if err != nil {
            return fmt.Errorf("parse ports/server_ports %q: %w", portsSpec, err)
        }
    } else if portStr != "" {
        p, err := strconv.Atoi(portStr)
        if err != nil {
            return fmt.Errorf("parse server port: %w", err)
        }
        ports = []int{p}
    } else {
        return fmt.Errorf("server must include a port, or set ports / server_ports")
    }

    startPort := ports[0]
    if portStr != "" {
        if p, e := strconv.Atoi(portStr); e == nil {
            startPort = p
        }
    }
    // Initial single host:port for protocol header
    proxyAddress := net.JoinHostPort(host, strconv.Itoa(startPort))

    if conf.Sni == "" {
        conf.Sni = host
    }

    hopInterval, err := conf.HopInterval()
    if err != nil {
        return fmt.Errorf("parse hop_interval: %w", err)
    }
    if hopInterval < 5*time.Second {
        hopInterval = 5 * time.Second
    }

    var hopCtrl *hopping.Controller
    if len(ports) > 1 {
        hopCtrl = hopping.NewController(host, ports, startPort)
        hopCtrl.Start(hopInterval)
        logger.Info().
            Str("host", host).
            Ints("ports", ports).
            Dur("hop_interval", hopInterval).
            Str("current", hopCtrl.CurrentAddr()).
            Msg("port hopping enabled")
        defer hopCtrl.Stop()
    }

    tlsConfig := &tls.Config{
        NextProtos:         []string{"h3"},
        MinVersion:         tls.VersionTLS13,
        ServerName:         conf.Sni,
        InsecureSkipVerify: conf.AllowInsecure,
    }
    if conf.PinnedCertChainSha256 != "" {
        pinnedHash, err := base64.URLEncoding.DecodeString(conf.PinnedCertChainSha256)
        if err != nil {
            pinnedHash, err = base64.StdEncoding.DecodeString(conf.PinnedCertChainSha256)
            if err != nil {
                pinnedHash, err = hex.DecodeString(conf.PinnedCertChainSha256)
                if err != nil {
                    return fmt.Errorf("failed to decode PinnedCertChainSha256")
                }
            }
        }
        tlsConfig.InsecureSkipVerify = true
        tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            if !bytes.Equal(common.GenerateCertChainHash(rawCerts), pinnedHash) {
                return fmt.Errorf("pinned hash of cert chain does not match")
            }
            return nil
        }
    }

    d, err := juicity.NewDialer(dialer.NewClientDialer(conf, hopCtrl), protocol.Header{
        ProxyAddress: proxyAddress,
        Feature1:     conf.CongestionControl,
        TlsConfig:    tlsConfig,
        User:         conf.Uuid,
        Password:     conf.Password,
        IsClient:     true,
        Flags:        0,
    })
    if err != nil {
        return err
    }
    if conf.Listen == "" && len(conf.Forward) == 0 {
        logger.Fatal().Msg("Please fill in at least one of `listen` and `forward` in the config file.")
    }
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    wg := pool.New().WithErrors().WithContext(ctx).WithCancelOnError()
    if conf.Listen != "" {
        s, err := server.NewMixed("mixed://"+conf.Listen, d)
        if err != nil {
            return err
        }
        wg.Go(func(ctx context.Context) error {
            ch := make(chan struct{}, 1)
            go func() {
                s.ListenAndServe()
                ch <- struct{}{}
            }()
            select {
            case <-ch:
                return fmt.Errorf("ListenAndServe: unexpected error")
            case <-ctx.Done():
                return nil
            }
        })
    }
    if len(conf.Forward) != 0 {
        for local, remote := range conf.Forward {
            local, remote := local, remote
            forwarder, err := server.NewForwarder(server.ForwarderOptions{
                Logger:     logger,
                Dialer:     d,
                LocalAddr:  local,
                RemoteAddr: remote,
            })
            if err != nil {
                return err
            }
            wg.Go(func(ctx context.Context) (err error) {
                ch := make(chan error, 1)
                go func() {
                    ch <- forwarder.Serve()
                }()
                select {
                case err := <-ch:
                    return err
                case <-ctx.Done():
                    return nil
                }
            })
        }
    }
    return wg.Wait()
}

// splitServer parses conf.Server which may be:
//   - "host"
//   - "host:port"
//   - "[ipv6]:port"
//   - bare IPv6 without port (e.g. "2001:db8::1")
func splitServer(server string) (host, port string, err error) {
    server = strings.TrimSpace(server)
    if server == "" {
        return "", "", fmt.Errorf("empty server")
    }

    // Bracketed IPv6: [addr]:port or [addr]
    if strings.HasPrefix(server, "[") {
        host, port, err = net.SplitHostPort(server)
        if err != nil {
            // "[addr]" without port
            if strings.HasSuffix(server, "]") {
                return server[1 : len(server)-1], "", nil
            }
            return "", "", err
        }
        return host, port, nil
    }

    // Bare IPv6 (contains ':' but net.SplitHostPort would fail without brackets)
    if ip := net.ParseIP(server); ip != nil {
        return server, "", nil
    }

    // host:port or hostname
    if strings.Count(server, ":") == 1 {
        host, port, err = net.SplitHostPort(server)
        if err != nil {
            return "", "", err
        }
        return host, port, nil
    }

    // hostname without port
    return server, "", nil
}

func init() {
    rootCmd.Version = shared.GetVersion(cgoEnabled)
    rootCmd.AddCommand(runCmd)
    shared.InitArgumentsFlags(runCmd)
}
