package config

import (
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
    Server                string            `json:"server"`
    Ports                 string            `json:"ports,omitempty"`        // Windows 风格: "3000-3100"
    ServerPorts           string            `json:"server_ports,omitempty"` // 兼容旧字段
    HopIntervalRaw        json.RawMessage   `json:"hop_interval,omitempty"` // 支持 10 或 "10s"
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

// PortRange 优先 ports，其次 server_ports。
func (c *Config) PortRange() string {
    if s := strings.TrimSpace(c.Ports); s != "" {
        return s
    }
    return strings.TrimSpace(c.ServerPorts)
}

// HopInterval 解析数字秒或 Go duration（"10" / 10 / "30s" / "1m"），默认 30s。
func (c *Config) HopInterval() (time.Duration, error) {
    if len(c.HopIntervalRaw) == 0 {
        return 30 * time.Second, nil
    }
    raw := strings.TrimSpace(string(c.HopIntervalRaw))
    // JSON number: 10
    if n, err := strconv.Atoi(raw); err == nil {
        if n < 5 {
            n = 5
        }
        return time.Duration(n) * time.Second, nil
    }
    // JSON string: "10" / "30s" / "1m"
    if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
        raw = raw[1 : len(raw)-1]
    }
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return 30 * time.Second, nil
    }
    if n, err := strconv.Atoi(raw); err == nil {
        if n < 5 {
            n = 5
        }
        return time.Duration(n) * time.Second, nil
    }
    d, err := time.ParseDuration(raw)
    if err != nil {
        return 0, fmt.Errorf("invalid hop_interval %q: %w", raw, err)
    }
    if d < 5*time.Second {
        d = 5 * time.Second
    }
    return d, nil
}
