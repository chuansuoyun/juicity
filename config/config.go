package config

import (
    "bytes"
    "encoding/json"
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"
)

var (
    Version = "unknown"
)

type Config struct {
    // Client
    Server string `json:"server"`
    // Port hopping range. Prefer "ports" (Windows client); "server_ports" kept for compatibility.
    ServerPorts string `json:"server_ports,omitempty"`
    Ports       string `json:"ports,omitempty"`
    // hop_interval: number seconds (10) or duration string ("30s")
    HopIntervalRaw json.RawMessage `json:"hop_interval,omitempty"`

    Uuid                  string            `json:"uuid"`
    Password              string            `json:"password"`
    Sni                   string            `json:"sni"`
    AllowInsecure         bool              `json:"allow_insecure"`
    PinnedCertChainSha256 string            `json:"pinned_certchain_sha256"`
    ProtectPath           string            `json:"protect_path"`
    Forward               map[string]string `json:"forward"`

    // Server
    Users                 map[string]string `json:"users"`
    Certificate           string            `json:"certificate"`
    PrivateKey            string            `json:"private_key"`
    Fwmark                string            `json:"fwmark"`
    SendThrough           string            `json:"send_through"`
    DialerLink            string            `json:"dialer_link"`
    DisableOutboundUdp443 bool              `json:"disable_outbound_udp443"`

    // Common
    Listen            string `json:"listen"`
    CongestionControl string `json:"congestion_control"`
    LogLevel          string `json:"log_level"`
}

func ReadConfig(p string) (*Config, error) {
    f, err := os.Open(p)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    var c Config
    if err = json.NewDecoder(f).Decode(&c); err != nil {
        return nil, err
    }
    return &c, nil
}

// PortRange returns the hop port specification.
// Prefer "ports" (Windows client), fall back to "server_ports".
func (c *Config) PortRange() string {
    if s := strings.TrimSpace(c.Ports); s != "" {
        return s
    }
    return strings.TrimSpace(c.ServerPorts)
}

// HopInterval parses hop_interval as:
//   - JSON number: 10 -> 10s
//   - JSON string: "10", "10s", "1m", etc.
// Default: 30s. Minimum applied by caller if desired (e.g. 5s).
func (c *Config) HopInterval() (time.Duration, error) {
    raw := bytes.TrimSpace(c.HopIntervalRaw)
    if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
        return 30 * time.Second, nil
    }

    // Numeric seconds: 10
    if raw[0] != '"' {
        var sec float64
        if err := json.Unmarshal(raw, &sec); err != nil {
            return 0, fmt.Errorf("parse hop_interval number: %w", err)
        }
        if sec <= 0 {
            return 30 * time.Second, nil
        }
        return time.Duration(sec * float64(time.Second)), nil
    }

    // String: "10s" / "10" / "1m"
    var s string
    if err := json.Unmarshal(raw, &s); err != nil {
        return 0, fmt.Errorf("parse hop_interval string: %w", err)
    }
    s = strings.TrimSpace(s)
    if s == "" {
        return 30 * time.Second, nil
    }
    // Pure digits -> seconds
    if _, err := strconv.Atoi(s); err == nil {
        n, _ := strconv.Atoi(s)
        if n <= 0 {
            return 30 * time.Second, nil
        }
        return time.Duration(n) * time.Second, nil
    }
    d, err := time.ParseDuration(s)
    if err != nil {
        return 0, fmt.Errorf("parse hop_interval duration %q: %w", s, err)
    }
    if d <= 0 {
        return 30 * time.Second, nil
    }
    return d, nil
}
