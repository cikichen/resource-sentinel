package config

import (
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Monitor MonitorConfig `yaml:"monitor"`
	Network NetworkConfig `yaml:"network"`
	Notify  NotifyConfig  `yaml:"notify"`
	Web     WebConfig     `yaml:"web"`
}

type MonitorConfig struct {
	Interval    time.Duration  `yaml:"interval"`
	CPUWindow   time.Duration  `yaml:"cpu_window"`
	DiskPath    string         `yaml:"disk_path"`
	Consecutive int            `yaml:"consecutive"`
	Thresholds  ThresholdsConf `yaml:"thresholds"`
}

type ThresholdsConf struct {
	CPU    float64 `yaml:"cpu"`
	Memory float64 `yaml:"memory"`
	Disk   float64 `yaml:"disk"`
}

type NetworkConfig struct {
	ProxyURL string `yaml:"proxy_url"`
}

type NotifyConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	WeChat   WeChatConfig   `yaml:"wechat"`
	IYUU     IYUUConfig     `yaml:"iyuu"`
	Webhook  WebhookConfig  `yaml:"webhook"`
	PushPlus PushPlusConfig `yaml:"pushplus"`
}

type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	ChatID  string `yaml:"chat_id"`
	APIBase string `yaml:"api_base"`
}

type WeChatConfig struct {
	Enabled bool   `yaml:"enabled"`
	Webhook string `yaml:"webhook"`
}

type IYUUConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

type PushPlusConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Token    string `yaml:"token"`
	Template string `yaml:"template"`
	Topic    string `yaml:"topic"`
}

type WebConfig struct {
	Enabled            bool     `yaml:"enabled"`
	Listen             string   `yaml:"listen"`
	AuthToken          string   `yaml:"auth_token"`
	AllowedCIDRs       []string `yaml:"allowed_cidrs"`
	RateLimitPerMinute int      `yaml:"rate_limit_per_minute"`
}

func Default() Config {
	return Config{
		Monitor: MonitorConfig{
			Interval:    10 * time.Minute,
			CPUWindow:   time.Second,
			DiskPath:    "/",
			Consecutive: 3,
			Thresholds: ThresholdsConf{
				CPU:    85,
				Memory: 80,
				Disk:   90,
			},
		},
		Web: WebConfig{
			Enabled:            false,
			Listen:             "127.0.0.1:8080",
			RateLimitPerMinute: 120,
		},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := parseYAML(data)
	if err != nil {
		return Config{}, err
	}

	if err := applyEnvOverrides(&cfg); err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func ParseAndValidateYAML(data []byte) (Config, error) {
	cfg, err := parseYAML(data)
	if err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseYAML(data []byte) (Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config yaml: %w", err)
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) error {
	setDuration := func(env string, dest *time.Duration) error {
		value := strings.TrimSpace(os.Getenv(env))
		if value == "" {
			return nil
		}
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse %s: %w", env, err)
		}
		*dest = d
		return nil
	}

	setString := func(env string, dest *string) {
		value := strings.TrimSpace(os.Getenv(env))
		if value != "" {
			*dest = value
		}
	}

	setBool := func(env string, dest *bool) error {
		value := strings.TrimSpace(os.Getenv(env))
		if value == "" {
			return nil
		}
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("parse %s: %w", env, err)
		}
		*dest = parsed
		return nil
	}

	setInt := func(env string, dest *int) error {
		value := strings.TrimSpace(os.Getenv(env))
		if value == "" {
			return nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse %s: %w", env, err)
		}
		*dest = parsed
		return nil
	}

	setFloat := func(env string, dest *float64) error {
		value := strings.TrimSpace(os.Getenv(env))
		if value == "" {
			return nil
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("parse %s: %w", env, err)
		}
		*dest = parsed
		return nil
	}

	if err := setDuration("APP_MONITOR_INTERVAL", &cfg.Monitor.Interval); err != nil {
		return err
	}
	if err := setDuration("APP_MONITOR_CPU_WINDOW", &cfg.Monitor.CPUWindow); err != nil {
		return err
	}
	setString("APP_MONITOR_DISK_PATH", &cfg.Monitor.DiskPath)
	if err := setInt("APP_MONITOR_CONSECUTIVE", &cfg.Monitor.Consecutive); err != nil {
		return err
	}
	if err := setFloat("APP_THRESHOLD_CPU", &cfg.Monitor.Thresholds.CPU); err != nil {
		return err
	}
	if err := setFloat("APP_THRESHOLD_MEMORY", &cfg.Monitor.Thresholds.Memory); err != nil {
		return err
	}
	if err := setFloat("APP_THRESHOLD_DISK", &cfg.Monitor.Thresholds.Disk); err != nil {
		return err
	}

	setString("APP_PROXY_URL", &cfg.Network.ProxyURL)

	if err := setBool("APP_TG_ENABLED", &cfg.Notify.Telegram.Enabled); err != nil {
		return err
	}
	setString("APP_TG_TOKEN", &cfg.Notify.Telegram.Token)
	setString("APP_TG_CHAT_ID", &cfg.Notify.Telegram.ChatID)
	setString("APP_TG_API_BASE", &cfg.Notify.Telegram.APIBase)

	if err := setBool("APP_WECHAT_ENABLED", &cfg.Notify.WeChat.Enabled); err != nil {
		return err
	}
	setString("APP_WECHAT_WEBHOOK", &cfg.Notify.WeChat.Webhook)

	if err := setBool("APP_IYUU_ENABLED", &cfg.Notify.IYUU.Enabled); err != nil {
		return err
	}
	setString("APP_IYUU_TOKEN", &cfg.Notify.IYUU.Token)

	if err := setBool("APP_WEBHOOK_ENABLED", &cfg.Notify.Webhook.Enabled); err != nil {
		return err
	}
	setString("APP_WEBHOOK_URL", &cfg.Notify.Webhook.URL)

	if err := setBool("APP_PUSHPLUS_ENABLED", &cfg.Notify.PushPlus.Enabled); err != nil {
		return err
	}
	setString("APP_PUSHPLUS_TOKEN", &cfg.Notify.PushPlus.Token)
	setString("APP_PUSHPLUS_TEMPLATE", &cfg.Notify.PushPlus.Template)
	setString("APP_PUSHPLUS_TOPIC", &cfg.Notify.PushPlus.Topic)

	if err := setBool("APP_WEB_ENABLED", &cfg.Web.Enabled); err != nil {
		return err
	}
	setString("APP_WEB_LISTEN", &cfg.Web.Listen)
	setString("APP_WEB_AUTH_TOKEN", &cfg.Web.AuthToken)
	setCSV("APP_WEB_ALLOWED_CIDRS", &cfg.Web.AllowedCIDRs)
	if err := setInt("APP_WEB_RATE_LIMIT_PER_MINUTE", &cfg.Web.RateLimitPerMinute); err != nil {
		return err
	}

	return nil
}

func setCSV(env string, dest *[]string) {
	value := strings.TrimSpace(os.Getenv(env))
	if value == "" {
		return
	}

	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			items = append(items, item)
		}
	}
	*dest = items
}

func Validate(cfg Config) error {
	if cfg.Monitor.Interval <= 0 {
		return fmt.Errorf("monitor.interval must be > 0")
	}
	if cfg.Monitor.CPUWindow <= 0 {
		return fmt.Errorf("monitor.cpu_window must be > 0")
	}
	if cfg.Monitor.Consecutive <= 0 {
		return fmt.Errorf("monitor.consecutive must be > 0")
	}

	thresholds := []struct {
		name  string
		value float64
	}{
		{name: "monitor.thresholds.cpu", value: cfg.Monitor.Thresholds.CPU},
		{name: "monitor.thresholds.memory", value: cfg.Monitor.Thresholds.Memory},
		{name: "monitor.thresholds.disk", value: cfg.Monitor.Thresholds.Disk},
	}

	for _, threshold := range thresholds {
		if threshold.value <= 0 || threshold.value > 100 {
			return fmt.Errorf("%s must be between 0 and 100", threshold.name)
		}
	}

	if cfg.Web.Enabled && strings.TrimSpace(cfg.Web.Listen) == "" {
		return fmt.Errorf("web.listen must be configured when web.enabled=true")
	}

	if strings.TrimSpace(cfg.Notify.Telegram.APIBase) != "" {
		if err := validateHTTPBaseURL(cfg.Notify.Telegram.APIBase); err != nil {
			return fmt.Errorf("notify.telegram.api_base is invalid: %w", err)
		}
	}
	if strings.TrimSpace(cfg.Network.ProxyURL) != "" {
		if err := validateProxyURL(cfg.Network.ProxyURL); err != nil {
			return fmt.Errorf("network.proxy_url is invalid: %w", err)
		}
	}
	if cfg.Web.Enabled {
		if cfg.Web.RateLimitPerMinute <= 0 {
			return fmt.Errorf("web.rate_limit_per_minute must be > 0")
		}

		listen := strings.TrimSpace(cfg.Web.Listen)
		if strings.TrimSpace(cfg.Web.AuthToken) == "" && !isLoopbackListen(listen) {
			return fmt.Errorf("web.auth_token is required when web.listen is not loopback")
		}

		for _, cidr := range cfg.Web.AllowedCIDRs {
			if err := validateCIDROrIP(cidr); err != nil {
				return fmt.Errorf("web.allowed_cidrs contains invalid entry %q: %w", cidr, err)
			}
		}
	}

	return nil
}

func isLoopbackListen(listen string) bool {
	host := listen
	if strings.Contains(listen, ":") {
		parsedHost, _, err := net.SplitHostPort(listen)
		if err == nil {
			host = parsedHost
		}
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateCIDROrIP(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("empty value")
	}
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return err
		}
		return nil
	}
	if ip := net.ParseIP(value); ip == nil {
		return fmt.Errorf("invalid ip")
	}
	return nil
}

func validateHTTPBaseURL(value string) error {
	parsed, err := neturl.Parse(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("host is required")
	}
	return nil
}

func validateProxyURL(value string) error {
	parsed, err := neturl.Parse(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	switch parsed.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("scheme must be http, https, socks5 or socks5h")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("host is required")
	}
	return nil
}
