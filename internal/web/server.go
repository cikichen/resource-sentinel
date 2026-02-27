package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"resource-sentinel/internal/config"
	"resource-sentinel/internal/monitor"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Server struct {
	httpServer *http.Server
}

type handler struct {
	configPath  string
	authToken   string
	authTokenMu sync.RWMutex
	sessionKey  []byte
	allowedNets []*net.IPNet
	rateLimiter *ipRateLimiter
}

type ipRateLimiter struct {
	limit int
	mu    sync.Mutex
	hits  map[string]rateHit
}

type rateHit struct {
	windowStart time.Time
	count       int
}

type rawConfigPayload struct {
	Content string `json:"content"`
}

type setupStatusPayload struct {
	Required bool `json:"required"`
}

type setupAuthPayload struct {
	Token    string `json:"token"`
	Remember bool   `json:"remember"`
}

type authLoginPayload struct {
	Token    string `json:"token"`
	Remember bool   `json:"remember"`
}

type authStatusPayload struct {
	SetupRequired bool `json:"setup_required"`
	Authenticated bool `json:"authenticated"`
}

type runtimeSamplePayload struct {
	CPU    float64 `json:"cpu"`
	Memory float64 `json:"memory"`
	Disk   float64 `json:"disk"`
	At     string  `json:"at"`
}

type runtimePayload struct {
	Sample runtimeSamplePayload `json:"sample"`
}

const bootstrapAuthToken = "CHANGE_ME_STRONG_TOKEN"
const sessionCookieName = "config_session"

type visualConfig struct {
	Monitor visualMonitorConfig `json:"monitor"`
	Network visualNetworkConfig `json:"network"`
	Notify  visualNotifyConfig  `json:"notify"`
	Web     visualWebConfig     `json:"web"`
}

type visualMonitorConfig struct {
	Interval    string                 `json:"interval"`
	CPUWindow   string                 `json:"cpu_window"`
	DiskPath    string                 `json:"disk_path"`
	Consecutive int                    `json:"consecutive"`
	Thresholds  visualThresholdsConfig `json:"thresholds"`
}

type visualThresholdsConfig struct {
	CPU    float64 `json:"cpu"`
	Memory float64 `json:"memory"`
	Disk   float64 `json:"disk"`
}

type visualNetworkConfig struct {
	ProxyURL string `json:"proxy_url"`
}

type visualNotifyConfig struct {
	Telegram visualTelegramConfig `json:"telegram"`
	WeChat   visualWeChatConfig   `json:"wechat"`
	IYUU     visualIYUUConfig     `json:"iyuu"`
	Webhook  visualWebhookConfig  `json:"webhook"`
	PushPlus visualPushPlusConfig `json:"pushplus"`
}

type visualTelegramConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	ChatID  string `json:"chat_id"`
	APIBase string `json:"api_base"`
}

type visualWeChatConfig struct {
	Enabled bool   `json:"enabled"`
	Webhook string `json:"webhook"`
}

type visualIYUUConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
}

type visualWebhookConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

type visualPushPlusConfig struct {
	Enabled  bool   `json:"enabled"`
	Token    string `json:"token"`
	Template string `json:"template"`
	Topic    string `json:"topic"`
}

type visualWebConfig struct {
	Enabled            bool     `json:"enabled"`
	Listen             string   `json:"listen"`
	AuthToken          string   `json:"auth_token"`
	HasAuthToken       bool     `json:"has_auth_token"`
	AllowedCIDRs       []string `json:"allowed_cidrs"`
	RateLimitPerMinute int      `json:"rate_limit_per_minute"`
}

type yamlConfig struct {
	Monitor yamlMonitorConfig `yaml:"monitor"`
	Network yamlNetworkConfig `yaml:"network"`
	Notify  yamlNotifyConfig  `yaml:"notify"`
	Web     yamlWebConfig     `yaml:"web"`
}

type yamlMonitorConfig struct {
	Interval    string               `yaml:"interval"`
	CPUWindow   string               `yaml:"cpu_window"`
	DiskPath    string               `yaml:"disk_path"`
	Consecutive int                  `yaml:"consecutive"`
	Thresholds  yamlThresholdsConfig `yaml:"thresholds"`
}

type yamlThresholdsConfig struct {
	CPU    float64 `yaml:"cpu"`
	Memory float64 `yaml:"memory"`
	Disk   float64 `yaml:"disk"`
}

type yamlNetworkConfig struct {
	ProxyURL string `yaml:"proxy_url"`
}

type yamlNotifyConfig struct {
	Telegram yamlTelegramConfig `yaml:"telegram"`
	WeChat   yamlWeChatConfig   `yaml:"wechat"`
	IYUU     yamlIYUUConfig     `yaml:"iyuu"`
	Webhook  yamlWebhookConfig  `yaml:"webhook"`
	PushPlus yamlPushPlusConfig `yaml:"pushplus"`
}

type yamlTelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	ChatID  string `yaml:"chat_id"`
	APIBase string `yaml:"api_base"`
}

type yamlWeChatConfig struct {
	Enabled bool   `yaml:"enabled"`
	Webhook string `yaml:"webhook"`
}

type yamlIYUUConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
}

type yamlWebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

type yamlPushPlusConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Token    string `yaml:"token"`
	Template string `yaml:"template"`
	Topic    string `yaml:"topic"`
}

type yamlWebConfig struct {
	Enabled            bool     `yaml:"enabled"`
	Listen             string   `yaml:"listen"`
	AuthToken          string   `yaml:"auth_token"`
	AllowedCIDRs       []string `yaml:"allowed_cidrs"`
	RateLimitPerMinute int      `yaml:"rate_limit_per_minute"`
}

func NewServer(listenAddr, configPath, authToken string, allowedCIDRs []string, rateLimitPerMinute int, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	h := NewHandlerWithOptions(configPath, authToken, allowedCIDRs, rateLimitPerMinute)
	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return &Server{httpServer: httpServer}
}

func (s *Server) Start() error {
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func NewHandler(configPath, authToken string) http.Handler {
	return NewHandlerWithOptions(configPath, authToken, nil, 120)
}

func NewHandlerWithOptions(configPath, authToken string, allowedCIDRs []string, rateLimitPerMinute int) http.Handler {
	if rateLimitPerMinute <= 0 {
		rateLimitPerMinute = 120
	}

	h := &handler{
		configPath:  configPath,
		authToken:   strings.TrimSpace(authToken),
		sessionKey:  newSessionKey(),
		allowedNets: parseAllowedCIDRs(allowedCIDRs),
		rateLimiter: &ipRateLimiter{
			limit: rateLimitPerMinute,
			hits:  make(map[string]rateHit),
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleIndex)
	mux.HandleFunc("/api/auth/status", h.handleAuthStatus)
	mux.HandleFunc("/api/auth/login", h.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", h.handleAuthLogout)
	mux.HandleFunc("/api/setup/status", h.handleSetupStatus)
	mux.HandleFunc("/api/setup/auth", h.handleSetupAuth)
	mux.HandleFunc("/api/config", h.handleVisualConfig)
	mux.HandleFunc("/api/config/raw", h.handleRawConfig)
	mux.HandleFunc("/api/runtime", h.handleRuntime)
	mux.HandleFunc("/healthz", h.handleHealthz)

	return mux
}

func (h *handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w)
		return
	}
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, indexHTML)
}

func (h *handler) handleVisualConfig(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if h.requiresInitialSetup() {
		h.writeJSON(w, http.StatusForbidden, map[string]string{"error": "initial setup required"})
		return
	}
	if !h.authorized(r) {
		h.writeUnauthorized(w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.readVisualConfig(w)
	case http.MethodPost:
		h.saveVisualConfig(w, r)
	default:
		h.writeMethodNotAllowed(w)
	}
}

func (h *handler) readVisualConfig(w http.ResponseWriter) {
	cfg, err := h.loadCurrentConfig()
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.writeJSON(w, http.StatusOK, toVisualConfig(cfg))
}

func (h *handler) saveVisualConfig(w http.ResponseWriter, r *http.Request) {
	var payload visualConfig
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("parse request failed: %v", err)})
		return
	}

	cfg, err := payload.toConfig()
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid config: %v", err)})
		return
	}

	currentCfg, err := h.loadCurrentConfig()
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(payload.Web.AuthToken) == "" {
		cfg.Web.AuthToken = currentCfg.Web.AuthToken
	}
	normalizedToken, err := normalizeAuthTokenForStorage(cfg.Web.AuthToken)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid config: %v", err)})
		return
	}
	cfg.Web.AuthToken = normalizedToken

	if err := config.Validate(cfg); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid config: %v", err)})
		return
	}

	content, err := marshalVisualYAML(toPersistVisualConfig(cfg))
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("render config failed: %v", err)})
		return
	}

	if err := os.WriteFile(h.configPath, content, 0o644); err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("write config failed: %v", err)})
		return
	}

	h.setAuthToken(cfg.Web.AuthToken)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "配置已保存，访问口令已即时生效；其他配置重启后生效"})
}

func (h *handler) handleRawConfig(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if h.requiresInitialSetup() {
		h.writeJSON(w, http.StatusForbidden, map[string]string{"error": "initial setup required"})
		return
	}
	if !h.authorized(r) {
		h.writeUnauthorized(w)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.readRawConfig(w)
	case http.MethodPost:
		h.saveRawConfig(w, r)
	default:
		h.writeMethodNotAllowed(w)
	}
}

func (h *handler) handleRuntime(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if h.requiresInitialSetup() {
		h.writeJSON(w, http.StatusForbidden, map[string]string{"error": "initial setup required"})
		return
	}
	if !h.authorized(r) {
		h.writeUnauthorized(w)
		return
	}
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w)
		return
	}

	cfg, err := h.loadCurrentConfig()
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	collector := monitor.NewSystemCollector(cfg.Monitor.DiskPath, cfg.Monitor.CPUWindow)
	sample, err := collector.Collect(r.Context())
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("collect runtime failed: %v", err)})
		return
	}

	h.writeJSON(w, http.StatusOK, runtimePayload{
		Sample: runtimeSamplePayload{
			CPU:    sample.CPU,
			Memory: sample.Memory,
			Disk:   sample.Disk,
			At:     sample.At.Format(time.RFC3339),
		},
	})
}

func (h *handler) readRawConfig(w http.ResponseWriter) {
	content, err := os.ReadFile(h.configPath)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("read config failed: %v", err)})
		return
	}

	h.writeJSON(w, http.StatusOK, rawConfigPayload{Content: string(content)})
}

func (h *handler) saveRawConfig(w http.ResponseWriter, r *http.Request) {
	var payload rawConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("parse request failed: %v", err)})
		return
	}

	if strings.TrimSpace(payload.Content) == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config content cannot be empty"})
		return
	}

	cfg, err := config.ParseAndValidateYAML([]byte(payload.Content))
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid config: %v", err)})
		return
	}
	normalizedToken, err := normalizeAuthTokenForStorage(cfg.Web.AuthToken)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid config: %v", err)})
		return
	}
	cfg.Web.AuthToken = normalizedToken

	content, err := marshalVisualYAML(toPersistVisualConfig(cfg))
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("render config failed: %v", err)})
		return
	}
	if err := os.WriteFile(h.configPath, content, 0o644); err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("write config failed: %v", err)})
		return
	}

	h.setAuthToken(cfg.Web.AuthToken)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "配置已保存，访问口令已即时生效；其他配置重启后生效"})
}

func (h *handler) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w)
		return
	}
	h.writeJSON(w, http.StatusOK, setupStatusPayload{Required: h.requiresInitialSetup()})
}

func (h *handler) handleSetupAuth(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w)
		return
	}
	if !h.requiresInitialSetup() {
		h.writeJSON(w, http.StatusConflict, map[string]string{"error": "initial setup already completed"})
		return
	}

	var payload setupAuthPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("parse request failed: %v", err)})
		return
	}
	token := strings.TrimSpace(payload.Token)
	normalizedToken, err := normalizeAuthTokenForStorage(token)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	cfg, err := h.loadCurrentConfig()
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cfg.Web.Enabled = true
	cfg.Web.AuthToken = normalizedToken
	if err := config.Validate(cfg); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid config: %v", err)})
		return
	}

	content, err := marshalVisualYAML(toPersistVisualConfig(cfg))
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("render config failed: %v", err)})
		return
	}
	if err := os.WriteFile(h.configPath, content, 0o644); err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("write config failed: %v", err)})
		return
	}

	h.setAuthToken(normalizedToken)
	h.setSessionCookie(w, payload.Remember)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "初始化口令已设置成功"})
}

func (h *handler) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w)
		return
	}
	if h.requiresInitialSetup() {
		h.writeJSON(w, http.StatusForbidden, map[string]string{"error": "initial setup required"})
		return
	}

	var payload authLoginPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("parse request failed: %v", err)})
		return
	}
	token := strings.TrimSpace(payload.Token)
	if !h.tokenMatches(token) {
		h.writeUnauthorized(w)
		return
	}

	h.setSessionCookie(w, payload.Remember)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "登录成功"})
}

func (h *handler) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w)
		return
	}

	setupRequired := h.requiresInitialSetup()
	authenticated := false
	if !setupRequired {
		expected := strings.TrimSpace(h.getAuthToken())
		if expected == "" || h.hasValidSession(r) {
			authenticated = true
		}
	}

	h.writeJSON(w, http.StatusOK, authStatusPayload{
		SetupRequired: setupRequired,
		Authenticated: authenticated,
	})
}

func (h *handler) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	h.setSecurityHeaders(w)
	if !h.preflightChecks(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		h.writeMethodNotAllowed(w)
		return
	}
	h.clearSessionCookie(w)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "已退出登录"})
}

func (h *handler) loadCurrentConfig() (config.Config, error) {
	content, err := os.ReadFile(h.configPath)
	if err != nil {
		return config.Config{}, fmt.Errorf("read config failed: %w", err)
	}
	cfg, err := config.ParseAndValidateYAML(content)
	if err != nil {
		return config.Config{}, fmt.Errorf("parse config failed: %w", err)
	}
	return cfg, nil
}

func toVisualConfig(cfg config.Config) visualConfig {
	return visualConfig{
		Monitor: visualMonitorConfig{
			Interval:    cfg.Monitor.Interval.String(),
			CPUWindow:   cfg.Monitor.CPUWindow.String(),
			DiskPath:    cfg.Monitor.DiskPath,
			Consecutive: cfg.Monitor.Consecutive,
			Thresholds: visualThresholdsConfig{
				CPU:    cfg.Monitor.Thresholds.CPU,
				Memory: cfg.Monitor.Thresholds.Memory,
				Disk:   cfg.Monitor.Thresholds.Disk,
			},
		},
		Network: visualNetworkConfig{
			ProxyURL: cfg.Network.ProxyURL,
		},
		Notify: visualNotifyConfig{
			Telegram: visualTelegramConfig{
				Enabled: cfg.Notify.Telegram.Enabled,
				Token:   cfg.Notify.Telegram.Token,
				ChatID:  cfg.Notify.Telegram.ChatID,
				APIBase: cfg.Notify.Telegram.APIBase,
			},
			WeChat: visualWeChatConfig{
				Enabled: cfg.Notify.WeChat.Enabled,
				Webhook: cfg.Notify.WeChat.Webhook,
			},
			IYUU: visualIYUUConfig{
				Enabled: cfg.Notify.IYUU.Enabled,
				Token:   cfg.Notify.IYUU.Token,
			},
			Webhook: visualWebhookConfig{
				Enabled: cfg.Notify.Webhook.Enabled,
				URL:     cfg.Notify.Webhook.URL,
			},
			PushPlus: visualPushPlusConfig{
				Enabled:  cfg.Notify.PushPlus.Enabled,
				Token:    cfg.Notify.PushPlus.Token,
				Template: cfg.Notify.PushPlus.Template,
				Topic:    cfg.Notify.PushPlus.Topic,
			},
		},
		Web: visualWebConfig{
			Enabled:            cfg.Web.Enabled,
			Listen:             cfg.Web.Listen,
			AuthToken:          "",
			HasAuthToken:       hasConfiguredAuthToken(cfg.Web.AuthToken),
			AllowedCIDRs:       cfg.Web.AllowedCIDRs,
			RateLimitPerMinute: cfg.Web.RateLimitPerMinute,
		},
	}
}

func toPersistVisualConfig(cfg config.Config) visualConfig {
	v := toVisualConfig(cfg)
	v.Web.AuthToken = strings.TrimSpace(cfg.Web.AuthToken)
	v.Web.HasAuthToken = false
	return v
}

func (v visualConfig) toConfig() (config.Config, error) {
	interval, err := time.ParseDuration(strings.TrimSpace(v.Monitor.Interval))
	if err != nil {
		return config.Config{}, fmt.Errorf("monitor.interval: %w", err)
	}
	cpuWindow, err := time.ParseDuration(strings.TrimSpace(v.Monitor.CPUWindow))
	if err != nil {
		return config.Config{}, fmt.Errorf("monitor.cpu_window: %w", err)
	}

	cfg := config.Config{
		Monitor: config.MonitorConfig{
			Interval:    interval,
			CPUWindow:   cpuWindow,
			DiskPath:    strings.TrimSpace(v.Monitor.DiskPath),
			Consecutive: v.Monitor.Consecutive,
			Thresholds: config.ThresholdsConf{
				CPU:    v.Monitor.Thresholds.CPU,
				Memory: v.Monitor.Thresholds.Memory,
				Disk:   v.Monitor.Thresholds.Disk,
			},
		},
		Network: config.NetworkConfig{
			ProxyURL: strings.TrimSpace(v.Network.ProxyURL),
		},
		Notify: config.NotifyConfig{
			Telegram: config.TelegramConfig{
				Enabled: v.Notify.Telegram.Enabled,
				Token:   strings.TrimSpace(v.Notify.Telegram.Token),
				ChatID:  strings.TrimSpace(v.Notify.Telegram.ChatID),
				APIBase: strings.TrimSpace(v.Notify.Telegram.APIBase),
			},
			WeChat: config.WeChatConfig{
				Enabled: v.Notify.WeChat.Enabled,
				Webhook: strings.TrimSpace(v.Notify.WeChat.Webhook),
			},
			IYUU: config.IYUUConfig{
				Enabled: v.Notify.IYUU.Enabled,
				Token:   strings.TrimSpace(v.Notify.IYUU.Token),
			},
			Webhook: config.WebhookConfig{
				Enabled: v.Notify.Webhook.Enabled,
				URL:     strings.TrimSpace(v.Notify.Webhook.URL),
			},
			PushPlus: config.PushPlusConfig{
				Enabled:  v.Notify.PushPlus.Enabled,
				Token:    strings.TrimSpace(v.Notify.PushPlus.Token),
				Template: strings.TrimSpace(v.Notify.PushPlus.Template),
				Topic:    strings.TrimSpace(v.Notify.PushPlus.Topic),
			},
		},
		Web: config.WebConfig{
			Enabled:            v.Web.Enabled,
			Listen:             strings.TrimSpace(v.Web.Listen),
			AuthToken:          strings.TrimSpace(v.Web.AuthToken),
			AllowedCIDRs:       v.Web.AllowedCIDRs,
			RateLimitPerMinute: v.Web.RateLimitPerMinute,
		},
	}

	if cfg.Notify.PushPlus.Template == "" {
		cfg.Notify.PushPlus.Template = "txt"
	}
	if cfg.Monitor.DiskPath == "" {
		cfg.Monitor.DiskPath = "/"
	}
	if cfg.Web.Listen == "" {
		cfg.Web.Listen = ":8080"
	}
	if cfg.Web.RateLimitPerMinute <= 0 {
		cfg.Web.RateLimitPerMinute = 120
	}
	return cfg, nil
}

func marshalVisualYAML(v visualConfig) ([]byte, error) {
	y := yamlConfig{
		Monitor: yamlMonitorConfig{
			Interval:    v.Monitor.Interval,
			CPUWindow:   v.Monitor.CPUWindow,
			DiskPath:    v.Monitor.DiskPath,
			Consecutive: v.Monitor.Consecutive,
			Thresholds: yamlThresholdsConfig{
				CPU:    v.Monitor.Thresholds.CPU,
				Memory: v.Monitor.Thresholds.Memory,
				Disk:   v.Monitor.Thresholds.Disk,
			},
		},
		Network: yamlNetworkConfig{
			ProxyURL: v.Network.ProxyURL,
		},
		Notify: yamlNotifyConfig{
			Telegram: yamlTelegramConfig{
				Enabled: v.Notify.Telegram.Enabled,
				Token:   v.Notify.Telegram.Token,
				ChatID:  v.Notify.Telegram.ChatID,
				APIBase: v.Notify.Telegram.APIBase,
			},
			WeChat:   yamlWeChatConfig{Enabled: v.Notify.WeChat.Enabled, Webhook: v.Notify.WeChat.Webhook},
			IYUU:     yamlIYUUConfig{Enabled: v.Notify.IYUU.Enabled, Token: v.Notify.IYUU.Token},
			Webhook:  yamlWebhookConfig{Enabled: v.Notify.Webhook.Enabled, URL: v.Notify.Webhook.URL},
			PushPlus: yamlPushPlusConfig{Enabled: v.Notify.PushPlus.Enabled, Token: v.Notify.PushPlus.Token, Template: v.Notify.PushPlus.Template, Topic: v.Notify.PushPlus.Topic},
		},
		Web: yamlWebConfig{
			Enabled:            v.Web.Enabled,
			Listen:             v.Web.Listen,
			AuthToken:          v.Web.AuthToken,
			AllowedCIDRs:       v.Web.AllowedCIDRs,
			RateLimitPerMinute: v.Web.RateLimitPerMinute,
		},
	}

	out, err := yaml.Marshal(y)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}

func (h *handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeMethodNotAllowed(w)
		return
	}
	h.setSecurityHeaders(w)
	h.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) authorized(r *http.Request) bool {
	if h.hasValidSession(r) {
		return true
	}

	expected := h.getAuthToken()
	if expected == "" {
		return true
	}
	return false
}

func (h *handler) tokenMatches(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	expected := strings.TrimSpace(h.getAuthToken())
	if expected == "" {
		return true
	}
	if !isBcryptHash(expected) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(expected), []byte(token)) == nil
}

func (h *handler) getAuthToken() string {
	h.authTokenMu.RLock()
	defer h.authTokenMu.RUnlock()
	return h.authToken
}

func (h *handler) setAuthToken(token string) {
	h.authTokenMu.Lock()
	h.authToken = strings.TrimSpace(token)
	h.authTokenMu.Unlock()
}

func (h *handler) requiresInitialSetup() bool {
	token := strings.TrimSpace(h.getAuthToken())
	return token == bootstrapAuthToken
}

func newSessionKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("fallback-%d", time.Now().UnixNano())))
		copy(key, sum[:])
	}
	return key
}

func (h *handler) setSessionCookie(w http.ResponseWriter, remember bool) {
	expiry := time.Now().Add(12 * time.Hour)
	maxAge := 0
	if remember {
		expiry = time.Now().Add(30 * 24 * time.Hour)
		maxAge = int((30 * 24 * time.Hour).Seconds())
	}
	value := h.newSessionValue(expiry, h.sessionBindingValue())
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if maxAge > 0 {
		cookie.MaxAge = maxAge
		cookie.Expires = expiry
	}
	http.SetCookie(w, cookie)
}

func (h *handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *handler) hasValidSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return h.verifySessionValue(cookie.Value, h.sessionBindingValue())
}

func (h *handler) newSessionValue(expiry time.Time, binding string) string {
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		fallback := sha256.Sum256([]byte(fmt.Sprintf("nonce-%d", time.Now().UnixNano())))
		nonce = fallback[:18]
	}
	payload := fmt.Sprintf("%d.%x.%s", expiry.Unix(), nonce, binding)
	mac := hmac.New(sha256.New, h.sessionKey)
	_, _ = mac.Write([]byte(payload))
	signature := fmt.Sprintf("%x", mac.Sum(nil))
	return payload + "." + signature
}

func (h *handler) verifySessionValue(value, expectedBinding string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	payload := parts[0] + "." + parts[1] + "." + parts[2]
	signature := parts[3]
	mac := hmac.New(sha256.New, h.sessionKey)
	_, _ = mac.Write([]byte(payload))
	expectedSig := fmt.Sprintf("%x", mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
		return false
	}

	expiryUnix, err := parseInt64(parts[0])
	if err != nil {
		return false
	}
	if time.Now().After(time.Unix(expiryUnix, 0)) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedBinding)) != 1 {
		return false
	}
	return true
}

func (h *handler) sessionBindingValue() string {
	token := strings.TrimSpace(h.getAuthToken())
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}

func parseInt64(value string) (int64, error) {
	var result int64
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid number")
		}
		result = result*10 + int64(r-'0')
	}
	return result, nil
}

func isBcryptHash(value string) bool {
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}

func hasConfiguredAuthToken(token string) bool {
	trimmed := strings.TrimSpace(token)
	return trimmed != "" && trimmed != bootstrapAuthToken
}

func normalizeAuthTokenForStorage(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", nil
	}
	if token == bootstrapAuthToken {
		return "", fmt.Errorf("auth token cannot use bootstrap placeholder")
	}
	if isBcryptHash(token) {
		return token, nil
	}
	if len(token) < 8 {
		return "", fmt.Errorf("auth token must be at least 8 characters")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash auth token failed: %w", err)
	}
	return string(hashed), nil
}

func (h *handler) preflightChecks(w http.ResponseWriter, r *http.Request) bool {
	clientIP := clientIPFromRequest(r)
	if !h.clientAllowed(clientIP) {
		h.writeJSON(w, http.StatusForbidden, map[string]string{"error": "client ip is not allowed"})
		return false
	}
	if !h.rateLimiter.Allow(clientIP) {
		h.writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return false
	}
	return true
}

func (h *handler) clientAllowed(ip string) bool {
	if len(h.allowedNets) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range h.allowedNets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (h *handler) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
}

func clientIPFromRequest(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	host = strings.Trim(host, "[]")
	return strings.TrimSpace(host)
}

func parseAllowedCIDRs(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			if _, network, err := net.ParseCIDR(value); err == nil {
				result = append(result, network)
			}
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			maskBits := 32
			if ip.To4() == nil {
				maskBits = 128
			}
			result = append(result, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(maskBits, maskBits),
			})
		}
	}
	return result
}

func (l *ipRateLimiter) Allow(key string) bool {
	if key == "" {
		key = "unknown"
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	hit, ok := l.hits[key]
	if !ok || now.Sub(hit.windowStart) >= time.Minute {
		l.hits[key] = rateHit{windowStart: now, count: 1}
		return true
	}
	if hit.count >= l.limit {
		return false
	}
	hit.count++
	l.hits[key] = hit
	return true
}

func (h *handler) writeUnauthorized(w http.ResponseWriter) {
	h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

func (h *handler) writeMethodNotAllowed(w http.ResponseWriter) {
	h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (h *handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>资源哨兵控制台</title>
  <style>
    :root {
      --color-primary: #0f172a;
      --color-secondary: #334155;
      --color-cta: #0ea5e9;
      --color-bg: #eef6ff;
      --color-panel: #ffffff;
      --color-soft: #f3f8ff;
      --color-text: #020617;
      --color-muted: #475569;
      --color-line: #d6e3f3;
      --color-success: #15803d;
      --color-warning: #b45309;
      --color-danger: #b91c1c;
      --shadow-sm: 0 12px 24px rgba(15, 23, 42, 0.08);
      --shadow-md: 0 24px 60px rgba(15, 23, 42, 0.13);
      --radius-lg: 20px;
      --radius-md: 14px;
      --radius-sm: 10px;
      --anchor-offset: 120px;
    }

    * { box-sizing: border-box; }

    html { scroll-padding-top: var(--anchor-offset); }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--color-text);
      font-family: "Fira Sans", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", sans-serif;
      background:
        radial-gradient(1000px 500px at -15% 5%, rgba(14, 165, 233, 0.22), transparent 58%),
        radial-gradient(1200px 640px at 120% -10%, rgba(15, 23, 42, 0.14), transparent 60%),
        linear-gradient(180deg, #f8fbff 0%, #ecf5ff 100%);
      line-height: 1.5;
    }

    .hidden {
      display: none !important;
    }

    .boot-screen {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
    }

    .boot-card {
      width: min(560px, 100%);
      padding: 20px 22px;
      border-radius: 14px;
      border: 1px solid var(--color-line);
      background: var(--color-panel);
      box-shadow: var(--shadow-md);
      text-align: center;
    }

    .boot-card h1 {
      margin: 0 0 8px;
      font-size: 18px;
      color: var(--color-primary);
      font-family: "Fira Code", "JetBrains Mono", monospace;
    }

    .boot-card p {
      margin: 0;
      color: var(--color-muted);
      font-size: 13px;
    }

    .skip-link {
      position: fixed;
      left: 16px;
      top: -100px;
      background: var(--color-primary);
      color: #fff;
      padding: 10px 14px;
      border-radius: 10px;
      text-decoration: none;
      z-index: 120;
      transition: top .2s ease;
    }

    .skip-link:focus {
      top: 14px;
    }

    .auth-gate {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
    }

    .auth-layout {
      width: min(1080px, 100%);
      display: grid;
      grid-template-columns: 1.1fr .9fr;
      gap: 18px;
      align-items: stretch;
    }

    .auth-showcase,
    .auth-card {
      background: var(--color-panel);
      border: 1px solid var(--color-line);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-md);
      overflow: hidden;
    }

    .auth-showcase {
      position: relative;
      padding: 28px 30px;
      color: #e2e8f0;
      background:
        radial-gradient(600px 220px at 80% 0%, rgba(14, 165, 233, 0.42), transparent 58%),
        linear-gradient(145deg, #0f172a, #1e293b 58%, #0b4a6f 100%);
      display: grid;
      gap: 18px;
    }

    .auth-showcase h2 {
      margin: 0;
      font-family: "Fira Code", "JetBrains Mono", monospace;
      font-size: 32px;
      line-height: 1.15;
      letter-spacing: .2px;
      text-shadow: 0 0 12px rgba(14, 165, 233, 0.2);
    }

    .auth-showcase p {
      margin: 0;
      color: #bfdbfe;
      max-width: 56ch;
    }

    .auth-features {
      display: grid;
      gap: 10px;
    }

    .auth-feature {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      padding: 11px 12px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.34);
      border: 1px solid rgba(148, 163, 184, 0.26);
      backdrop-filter: blur(6px);
    }

    .auth-dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      margin-top: 6px;
      background: linear-gradient(145deg, #22d3ee, #0ea5e9);
      box-shadow: 0 0 0 5px rgba(14, 165, 233, 0.18);
      flex-shrink: 0;
    }

    .auth-feature strong {
      font-size: 14px;
      color: #f8fafc;
      display: block;
      margin-bottom: 2px;
    }

    .auth-feature span {
      color: #cbd5e1;
      font-size: 13px;
    }

    .auth-card {
      padding: 24px;
      display: grid;
      gap: 12px;
      align-content: center;
    }

    .auth-title {
      margin: 0;
      font-family: "Fira Code", "JetBrains Mono", monospace;
      color: var(--color-primary);
      font-size: 24px;
      line-height: 1.25;
    }

    .auth-desc {
      margin: 0;
      color: var(--color-muted);
      font-size: 13px;
    }

    .auth-field {
      display: grid;
      gap: 7px;
    }

    .auth-field label {
      font-size: 13px;
      font-weight: 700;
      color: var(--color-secondary);
    }

    .auth-input {
      min-height: 46px;
      border-radius: var(--radius-sm);
      border: 1px solid #c6d4e7;
      background: #fff;
      color: var(--color-text);
      padding: 11px 12px;
      font-size: 14px;
    }

    .auth-input:focus {
      border-color: #0ea5e9;
      box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.16);
      outline: none;
    }

    .auth-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
    }

    .auth-hint {
      margin: 0;
      min-height: 20px;
      font-size: 12px;
      color: var(--color-muted);
    }

    .shell {
      width: min(1440px, 100% - 32px);
      margin: 16px auto 30px;
      display: grid;
      gap: 14px;
    }

    .topbar {
      position: sticky;
      top: 8px;
      z-index: 60;
      background: rgba(255, 255, 255, 0.9);
      border: 1px solid var(--color-line);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-sm);
      padding: 14px;
      display: grid;
      gap: 12px;
      backdrop-filter: blur(10px);
    }

    .topbar-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
    }

    .brand-wrap {
      display: grid;
      gap: 3px;
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      font-family: "Fira Code", "JetBrains Mono", monospace;
      font-size: 15px;
      font-weight: 700;
      letter-spacing: .2px;
      color: var(--color-primary);
    }

    .brand-sub {
      margin: 0;
      color: #64748b;
      font-size: 12px;
      font-weight: 600;
    }

    .brand-mark {
      width: 13px;
      height: 13px;
      border-radius: 999px;
      background: linear-gradient(145deg, #0ea5e9, #0f172a);
      box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.18);
      flex-shrink: 0;
    }

    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }

    .status-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 12px;
      min-height: 38px;
      border-radius: 999px;
      border: 1px solid #cbd5e1;
      background: #e2e8f0;
      color: #0f172a;
      font-size: 13px;
      font-weight: 700;
      white-space: nowrap;
    }

    .status-chip[data-tone="ok"] {
      border-color: rgba(21, 128, 61, 0.24);
      background: rgba(21, 128, 61, 0.14);
      color: #166534;
    }

    .status-chip[data-tone="warn"] {
      border-color: rgba(180, 83, 9, 0.24);
      background: rgba(180, 83, 9, 0.12);
      color: #92400e;
    }

    .status-chip[data-tone="err"] {
      border-color: rgba(185, 28, 28, 0.24);
      background: rgba(185, 28, 28, 0.12);
      color: #991b1b;
    }

    .btn {
      min-height: 42px;
      border: 1px solid transparent;
      border-radius: var(--radius-sm);
      padding: 9px 14px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      transition: background-color .18s ease, border-color .18s ease, color .18s ease, box-shadow .18s ease;
      text-decoration: none;
      user-select: none;
    }

    .btn:disabled {
      opacity: .56;
      cursor: not-allowed;
    }

    .btn-primary {
      background: var(--color-cta);
      border-color: var(--color-cta);
      color: #fff;
    }

    .btn-primary:hover {
      background: #0284c7;
      border-color: #0284c7;
      box-shadow: 0 6px 18px rgba(14, 165, 233, 0.28);
    }

    .btn-secondary {
      background: #fff;
      border-color: #cbd5e1;
      color: var(--color-primary);
    }

    .btn-secondary:hover {
      background: #f8fafc;
      border-color: #94a3b8;
    }

    .btn-dark {
      background: var(--color-primary);
      border-color: var(--color-primary);
      color: #fff;
    }

    .btn-dark:hover {
      background: #1e293b;
      border-color: #1e293b;
    }

    .token-row {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      padding-top: 4px;
      border-top: 1px dashed var(--color-line);
    }

    .token-input {
      flex: 1 1 260px;
      min-width: 220px;
      min-height: 42px;
      border-radius: var(--radius-sm);
      border: 1px solid #cbd5e1;
      padding: 10px 12px;
      background: #fff;
      color: var(--color-text);
      font-size: 14px;
    }

    .token-input:focus {
      border-color: #0ea5e9;
      box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.16);
      outline: none;
    }

    .remember {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--color-muted);
      white-space: nowrap;
    }

    .workspace {
      display: grid;
      gap: 14px;
      grid-template-columns: 260px minmax(0, 1fr);
      align-items: start;
    }

    .side-panel {
      position: sticky;
      top: 12px;
      border-radius: var(--radius-lg);
      background: rgba(255, 255, 255, 0.84);
      border: 1px solid var(--color-line);
      box-shadow: var(--shadow-sm);
      padding: 14px;
      display: grid;
      gap: 12px;
      backdrop-filter: blur(8px);
    }

    .intro {
      margin: 0;
      color: var(--color-muted);
      font-size: 13px;
    }

    .toc {
      display: grid;
      gap: 8px;
    }

    .toc a {
      text-decoration: none;
      color: #0f172a;
      background: var(--color-soft);
      border: 1px solid var(--color-line);
      border-radius: 10px;
      padding: 10px 11px;
      font-size: 13px;
      font-weight: 700;
      transition: background-color .18s ease, border-color .18s ease;
      cursor: pointer;
    }

    .toc a:hover {
      background: #e2ecfb;
      border-color: #93b5d7;
    }

    .hint-list {
      margin: 0;
      padding-left: 18px;
      color: var(--color-muted);
      font-size: 12px;
      line-height: 1.55;
    }

    .content {
      display: grid;
      gap: 12px;
    }

    #overview,
    #group-monitor,
    #group-notify,
    #group-security,
    #advanced {
      scroll-margin-top: var(--anchor-offset);
    }

    .hero {
      border-radius: var(--radius-lg);
      border: 1px solid #aac9e9;
      box-shadow: var(--shadow-md);
      padding: 20px;
      background:
        radial-gradient(780px 240px at 84% -5%, rgba(14, 165, 233, 0.35), transparent 60%),
        linear-gradient(140deg, #0f172a 0%, #1e293b 60%, #0b4a6f 100%);
      color: #e2e8f0;
    }

    .hero h1 {
      margin: 0;
      font-family: "Fira Code", "JetBrains Mono", monospace;
      font-size: 28px;
      line-height: 1.2;
      letter-spacing: .1px;
      text-shadow: 0 0 10px rgba(14, 165, 233, 0.2);
    }

    .hero p {
      margin: 8px 0 0;
      max-width: 72ch;
      color: #cbd5e1;
      font-size: 14px;
    }

    .hero-metrics {
      margin-top: 12px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .hero-pill {
      display: inline-flex;
      align-items: center;
      border: 1px solid rgba(148, 163, 184, 0.4);
      border-radius: 999px;
      padding: 7px 11px;
      font-size: 12px;
      font-weight: 600;
      background: rgba(15, 23, 42, 0.4);
      color: #dbeafe;
    }

    .mode-card,
    .panel,
    .card,
    .raw-card {
      background: var(--color-panel);
      border: 1px solid var(--color-line);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-sm);
    }

    .mode-card {
      padding: 15px;
      display: grid;
      gap: 10px;
    }

    .mode-card h2,
    .raw-card h2 {
      margin: 0;
      font-size: 19px;
      font-weight: 700;
      letter-spacing: .12px;
      color: var(--color-primary);
    }

    .mode-card p,
    .raw-card p,
    .panel p {
      margin: 0;
      color: var(--color-muted);
      font-size: 13px;
    }

    .tabs {
      display: inline-flex;
      width: fit-content;
      padding: 4px;
      border-radius: 10px;
      border: 1px solid var(--color-line);
      background: var(--color-soft);
      gap: 4px;
    }

    .tab-btn {
      min-height: 38px;
      border: 0;
      border-radius: 8px;
      padding: 8px 14px;
      background: transparent;
      color: var(--color-muted);
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      transition: background-color .2s ease, color .2s ease, box-shadow .2s ease;
    }

    .tab-btn.active {
      background: #fff;
      color: var(--color-primary);
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
    }

    .tab-body { display: none; }
    .tab-body.active { display: block; }

    .dashboard-grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 12px;
    }

    .group-section {
      grid-column: span 12;
      display: grid;
      gap: 10px;
    }

    .group-head {
      padding: 2px 2px 0;
      display: grid;
      gap: 4px;
    }

    .group-head h3 {
      margin: 0;
      font-size: 15px;
      color: var(--color-primary);
      font-family: "Fira Code", "JetBrains Mono", monospace;
    }

    .group-head p {
      margin: 0;
      font-size: 12px;
      color: var(--color-muted);
    }

    .group-grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 12px;
    }

    .overview-card {
      padding: 15px;
      border-left: 4px solid var(--color-cta);
    }

    .overview-grid {
      margin-top: 10px;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }

    .overview-item {
      border: 1px solid #dce8f5;
      border-radius: 10px;
      background: #f7fbff;
      padding: 10px 11px;
      display: grid;
      gap: 6px;
      min-height: 78px;
    }

    .overview-label {
      font-size: 12px;
      color: var(--color-muted);
      font-weight: 700;
      letter-spacing: .08px;
    }

    .overview-item strong {
      font-size: 15px;
      color: var(--color-primary);
      line-height: 1.35;
    }

    .overview-risk {
      margin: 10px 0 0;
      border-radius: 10px;
      border: 1px solid #d9e2ec;
      background: #f8fafc;
      color: var(--color-secondary);
      padding: 10px 11px;
      font-size: 13px;
      font-weight: 600;
      line-height: 1.4;
    }

    .overview-risk[data-tone="ok"] {
      border-color: rgba(21, 128, 61, 0.2);
      background: rgba(21, 128, 61, 0.08);
      color: #166534;
    }

    .overview-risk[data-tone="warn"] {
      border-color: rgba(180, 83, 9, 0.2);
      background: rgba(180, 83, 9, 0.1);
      color: #92400e;
    }

    .card {
      padding: 15px;
    }

    .span-12 { grid-column: span 12; }
    .span-6 { grid-column: span 6; }
    .span-4 { grid-column: span 4; }

    .card h3 {
      margin: 0;
      font-size: 17px;
      color: var(--color-primary);
      font-family: "Fira Code", "JetBrains Mono", monospace;
      letter-spacing: .1px;
    }

    .card-header {
      margin-bottom: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .card-sub {
      margin: 0;
      color: var(--color-muted);
      font-size: 12px;
    }

    .fields {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 10px;
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .field.full { grid-column: span 2; }

    .field label {
      font-size: 13px;
      font-weight: 700;
      color: var(--color-secondary);
    }

    .field small {
      font-size: 12px;
      color: var(--color-muted);
    }

    .field input,
    .field select,
    textarea {
      width: 100%;
      min-height: 44px;
      border-radius: var(--radius-sm);
      border: 1px solid #c6d4e7;
      background: #fff;
      color: var(--color-text);
      padding: 10px 11px;
      font-size: 14px;
      font-family: inherit;
      transition: border-color .18s ease, box-shadow .18s ease, background-color .18s ease;
    }

    .field input:hover,
    .field select:hover,
    textarea:hover {
      border-color: #88a9cb;
    }

    .field input:focus,
    .field select:focus,
    textarea:focus {
      border-color: #0ea5e9;
      box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.16);
      outline: none;
    }

    .toggle {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px dashed #dbe4ee;
      gap: 8px;
    }

    .toggle:last-of-type {
      border-bottom: none;
      padding-bottom: 0;
    }

    .toggle label {
      font-size: 13px;
      font-weight: 700;
      color: var(--color-secondary);
    }

    .helper {
      font-size: 12px;
      color: var(--color-muted);
      margin-top: 10px;
      line-height: 1.55;
    }

    .raw-card {
      padding: 15px;
      display: grid;
      gap: 10px;
    }

    textarea {
      min-height: 420px;
      resize: vertical;
      font-family: "Fira Code", "JetBrains Mono", "SFMono-Regular", monospace;
      font-size: 13px;
      line-height: 1.55;
      background: #fbfdff;
    }

    .error {
      border-color: var(--color-danger) !important;
      box-shadow: 0 0 0 3px rgba(185, 28, 28, 0.14) !important;
      background: rgba(254, 242, 242, 0.55) !important;
    }

    :focus-visible {
      outline: 3px solid rgba(14, 165, 233, 0.35);
      outline-offset: 2px;
    }

    @media (max-width: 1120px) {
      .auth-layout,
      .workspace {
        grid-template-columns: 1fr;
      }
      .side-panel {
        position: static;
      }
    }

    @media (max-width: 900px) {
      .shell {
        width: min(1400px, 100% - 20px);
        margin-top: 10px;
      }
      .hero h1 {
        font-size: 24px;
      }
      .span-6,
      .span-4,
      .span-12 {
        grid-column: span 12;
      }
      .fields {
        grid-template-columns: 1fr;
      }
      .overview-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .field.full {
        grid-column: span 1;
      }
    }

    @media (max-width: 560px) {
      .auth-gate {
        padding: 14px;
      }
      .auth-card {
        padding: 16px;
      }
      .auth-showcase {
        padding: 20px 16px;
      }
      .overview-grid {
        grid-template-columns: 1fr;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        transition: none !important;
        animation: none !important;
        scroll-behavior: auto !important;
      }
    }
  </style>
</head>
<body>
  <section class="boot-screen" id="bootScreen" aria-live="polite" aria-label="启动中">
    <div class="boot-card">
      <h1>正在进入资源哨兵</h1>
      <p>正在检查登录状态与配置，请稍候…</p>
    </div>
  </section>

  <section class="auth-gate hidden" id="authGate" aria-label="登录页">
    <div class="auth-layout">
      <aside class="auth-showcase" aria-label="欢迎信息">
        <h2>资源哨兵</h2>
        <p>专注系统资源监控与告警：采集 CPU/内存/磁盘，连续超阈值触发告警，并在恢复后自动通知。</p>
        <div class="auth-features">
          <div class="auth-feature">
            <span class="auth-dot" aria-hidden="true"></span>
            <div><strong>连续阈值告警</strong><span>支持按连续次数触发，减少抖动误报。</span></div>
          </div>
          <div class="auth-feature">
            <span class="auth-dot" aria-hidden="true"></span>
            <div><strong>恢复状态通知</strong><span>指标回落到正常区间时自动发送恢复消息。</span></div>
          </div>
          <div class="auth-feature">
            <span class="auth-dot" aria-hidden="true"></span>
            <div><strong>多通道推送</strong><span>Telegram、企业微信、IYUU、PushPlus、Webhook 一体化配置。</span></div>
          </div>
        </div>
      </aside>
      <div class="auth-card">
        <h1 class="auth-title" id="authTitle">登录资源哨兵控制台</h1>
        <p class="auth-desc" id="authDesc">当服务器开启鉴权时，需要先验证访问口令。若未开启鉴权，将自动进入主页。</p>
        <div class="auth-field">
          <label for="login_token" id="loginTokenLabel">访问口令</label>
          <input id="login_token" class="auth-input" type="password" autocomplete="off" placeholder="输入访问口令后进入主页">
        </div>
        <div class="auth-field hidden" id="loginConfirmField">
          <label for="login_token_confirm">确认访问口令</label>
          <input id="login_token_confirm" class="auth-input" type="password" autocomplete="off" placeholder="再次输入访问口令">
        </div>
        <div class="auth-actions">
          <label class="remember"><input id="login_remember" type="checkbox">记住登录状态（30天）</label>
          <button class="btn btn-primary" id="loginBtn" type="button">进入主页</button>
        </div>
        <p class="auth-hint" id="loginHint">请输入口令后登录。</p>
      </div>
    </div>
  </section>

  <a class="skip-link hidden" id="skipLink" href="#main">跳转到主内容</a>

  <div class="shell hidden" id="appShell">
    <header class="topbar">
      <div class="topbar-row">
        <div class="brand-wrap">
          <div class="brand"><span class="brand-mark" aria-hidden="true"></span>资源哨兵控制台主页</div>
          <p class="brand-sub">低频巡检、连续告警、恢复通知，以更低资源占用持续守护主机。</p>
        </div>
        <div class="btn-row" aria-label="主操作">
          <button class="btn btn-secondary" id="reloadBtn" type="button">重新加载</button>
          <button class="btn btn-primary" id="saveBtn" type="button">保存配置</button>
          <button class="btn btn-secondary" id="logoutBtn" type="button">退出登录</button>
          <span class="status-chip hidden" id="status" data-tone="idle" aria-live="polite"></span>
        </div>
      </div>

    </header>

    <div class="workspace">
      <aside class="side-panel" aria-label="页面侧边栏">
        <p class="intro">日常使用推荐快速配置；高级 YAML 适合批量导入和精细调整。</p>
        <nav class="toc" aria-label="页面导航">
          <a href="#overview">状态总览</a>
          <a href="#group-monitor">监控配置</a>
          <a href="#group-notify">通知配置</a>
          <a href="#group-security">访问与安全</a>
          <a id="navAdvancedLink" href="#advanced">高级配置（YAML）</a>
        </nav>
        <ul class="hint-list">
          <li>访问口令保存后即时生效，其他配置需重启服务或容器生效</li>
          <li>所有核心操作支持键盘导航</li>
          <li>危险配置会在前端先做基础校验</li>
        </ul>
      </aside>

      <main class="content" id="main" tabindex="-1">
        <section class="hero" role="banner">
          <h1>资源巡检总览</h1>
          <p>面向低负载长期运行场景：按计划采样 CPU/内存/磁盘，连续超阈值才触发告警，恢复后自动通知。</p>
          <div class="hero-metrics" aria-label="能力摘要">
            <span class="hero-pill">10m 默认巡检</span>
            <span class="hero-pill">连续触发抑制抖动</span>
            <span class="hero-pill">恢复通知 + 多通道推送</span>
          </div>
        </section>

        <section class="mode-card">
          <h2>快速配置</h2>
          <p>快速配置覆盖大多数运维场景；高级配置（YAML）用于一次性批量变更。</p>
          <div class="btn-row">
            <button class="btn btn-secondary" id="openAdvancedBtn" type="button">进入高级配置（YAML）</button>
          </div>
        </section>

        <div class="tab-body active" id="tabVisual">
          <section class="dashboard-grid">
            <article class="card span-12 overview-card" id="overview" aria-live="polite">
              <div class="card-header">
                <h3>当前状态</h3>
                <p class="card-sub">展示告警阈值与配置风险摘要</p>
              </div>
              <div class="overview-grid">
                <div class="overview-item">
                  <span class="overview-label">告警阈值</span>
                  <strong id="ov_thresholds">-</strong>
                </div>
                <div class="overview-item">
                  <span class="overview-label">通知通道</span>
                  <strong id="ov_channels">-</strong>
                </div>
                <div class="overview-item">
                  <span class="overview-label">访问范围</span>
                  <strong id="ov_web_scope">-</strong>
                </div>
                <div class="overview-item">
                  <span class="overview-label">访问频率限制</span>
                  <strong id="ov_rate_limit">-</strong>
                </div>
              </div>
              <p class="overview-risk" id="ov_risk" data-tone="warn">-</p>
            </article>

            <section class="group-section" id="group-monitor" aria-labelledby="group-monitor-title">
              <div class="group-head">
                <h3 id="group-monitor-title">监控配置</h3>
                <p>配置采样周期、采样窗口、触发次数和告警阈值。</p>
              </div>
              <article class="card span-12" id="monitor">
                <div class="card-header">
                  <h3>监控策略</h3>
                  <p class="card-sub">建议低频采样，长期运行更省资源</p>
                </div>
                <div class="fields">
                  <div class="field">
                    <label for="monitor_interval">采样间隔</label>
                    <input id="monitor_interval" placeholder="10m">
                    <small>示例：10m / 30m / 1h</small>
                  </div>
                  <div class="field">
                    <label for="monitor_cpu_window">CPU 采样窗口</label>
                    <input id="monitor_cpu_window" placeholder="1s">
                  </div>
                  <div class="field">
                    <label for="monitor_disk_path">磁盘路径</label>
                    <input id="monitor_disk_path" placeholder="/">
                  </div>
                  <div class="field">
                    <label for="monitor_consecutive">连续触发次数</label>
                    <input id="monitor_consecutive" type="number" min="1">
                  </div>
                  <div class="field">
                    <label for="threshold_cpu">CPU 阈值 (%)</label>
                    <input id="threshold_cpu" type="number" min="0" max="100" step="0.1">
                  </div>
                  <div class="field">
                    <label for="threshold_memory">内存阈值 (%)</label>
                    <input id="threshold_memory" type="number" min="0" max="100" step="0.1">
                  </div>
                  <div class="field full">
                    <label for="threshold_disk">磁盘阈值 (%)</label>
                    <input id="threshold_disk" type="number" min="0" max="100" step="0.1">
                  </div>
                </div>
              </article>
            </section>

            <section class="group-section" id="group-notify" aria-labelledby="group-notify-title">
              <div class="group-head">
                <h3 id="group-notify-title">通知配置</h3>
                <p>按通道分组配置告警发送能力，可按你的使用场景单独启用。</p>
              </div>
              <div class="group-grid">
                <article class="card span-12" id="network-global">
                  <div class="card-header">
                    <h3>全局网络代理</h3>
                    <p class="card-sub">程序所有出网请求统一走代理（可选）</p>
                  </div>
                  <div class="fields">
                    <div class="field full">
                      <label for="network_proxy_url">代理地址（可选）</label>
                      <input id="network_proxy_url" placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080">
                      <small>支持 http / https / socks5 / socks5h，留空表示直连。</small>
                    </div>
                  </div>
                </article>

                <article class="card span-4" id="notify-main">
                  <div class="card-header">
                    <h3>Telegram</h3>
                    <p class="card-sub">主通道：适合即时告警触达</p>
                  </div>
                  <div class="toggle"><label for="tg_enabled">启用 Telegram</label><input id="tg_enabled" type="checkbox"></div>
                  <div class="fields">
                    <div class="field full"><label for="tg_token">Bot Token</label><input id="tg_token"></div>
                    <div class="field full"><label for="tg_chat_id">Chat ID</label><input id="tg_chat_id"></div>
                    <div class="field full"><label for="tg_api_base">自定义 API 地址（可选）</label><input id="tg_api_base" placeholder="https://api.telegram.org"></div>
                  </div>
                </article>

                <article class="card span-4" id="notify-team">
                  <div class="card-header">
                    <h3>企业微信 + IYUU</h3>
                    <p class="card-sub">团队协同与移动端提醒</p>
                  </div>
                  <div class="toggle"><label for="wechat_enabled">启用企业微信</label><input id="wechat_enabled" type="checkbox"></div>
                  <div class="field"><label for="wechat_webhook">企业微信 Webhook</label><input id="wechat_webhook"></div>
                  <div class="toggle"><label for="iyuu_enabled">启用 IYUU</label><input id="iyuu_enabled" type="checkbox"></div>
                  <div class="field"><label for="iyuu_token">IYUU Token</label><input id="iyuu_token"></div>
                </article>

                <article class="card span-4" id="notify-automation">
                  <div class="card-header">
                    <h3>Webhook + PushPlus</h3>
                    <p class="card-sub">外部系统与群组消息联动</p>
                  </div>
                  <div class="toggle"><label for="webhook_enabled">启用通用 Webhook</label><input id="webhook_enabled" type="checkbox"></div>
                  <div class="field"><label for="webhook_url">Webhook URL</label><input id="webhook_url"></div>
                  <hr style="border:none;border-top:1px dashed #dbe4ee;margin:12px 0;">
                  <div class="toggle"><label for="pushplus_enabled">启用 PushPlus</label><input id="pushplus_enabled" type="checkbox"></div>
                  <div class="fields">
                    <div class="field full"><label for="pushplus_token">PushPlus Token</label><input id="pushplus_token"></div>
                    <div class="field">
                      <label for="pushplus_template">模板</label>
                      <select id="pushplus_template">
                        <option value="txt">txt</option>
                        <option value="markdown">markdown</option>
                        <option value="html">html</option>
                        <option value="json">json</option>
                      </select>
                    </div>
                    <div class="field"><label for="pushplus_topic">Topic(可选)</label><input id="pushplus_topic"></div>
                  </div>
                </article>
              </div>
            </section>

            <section class="group-section" id="group-security" aria-labelledby="group-security-title">
              <div class="group-head">
                <h3 id="group-security-title">访问与安全</h3>
                <p>管理控制台访问范围、口令与限流策略。</p>
              </div>
              <article class="card span-12" id="web-security">
                <div class="card-header">
                  <h3>Web 安全</h3>
                  <p class="card-sub">公网访问建议同时启用口令、白名单与限流</p>
                </div>
                <div class="fields">
                  <div class="field">
                    <label>Web 控制台状态</label>
                    <input value="默认启用（当前版本不提供禁用开关）" readonly>
                  </div>
                  <div class="field"><label for="web_listen">监听地址</label><input id="web_listen" placeholder=":8080"></div>
                  <div class="field"><label for="web_rate_limit">限流(每 IP 每分钟)</label><input id="web_rate_limit" type="number" min="1" placeholder="120"></div>
                  <div class="field"><label for="web_allowed_cidrs">白名单 CIDR/IP</label><input id="web_allowed_cidrs" placeholder="10.0.0.0/8,192.168.1.10"></div>
                  <div class="field full"><label for="web_auth_token">访问口令</label><input id="web_auth_token" placeholder="公网部署时必须配置强口令"></div>
                </div>
                <p class="helper">若监听地址不是 127.0.0.1 / localhost，建议至少配置强口令与来源白名单。访问口令保存后立即生效。</p>
              </article>
            </section>
          </section>
        </div>

        <div class="tab-body" id="tabRaw">
          <section class="raw-card" id="advanced">
            <h2>高级 YAML 编辑</h2>
            <p>该模式面向高级用户。请确认你清楚 YAML 结构后再编辑，保存前后会由服务端执行语法与阈值校验。</p>
            <textarea id="raw_editor" spellcheck="false" aria-label="YAML 编辑器"></textarea>
            <p class="helper">快速配置与高级配置操作同一份配置。切换前建议先保存当前修改。</p>
            <div class="btn-row">
              <button class="btn btn-dark" id="saveRawBtn" type="button">保存 YAML</button>
              <button class="btn btn-secondary" id="backVisualBtn" type="button">返回快速配置</button>
            </div>
          </section>
        </div>

      </main>
    </div>
  </div>

  <script>
    const statusEl = document.getElementById('status');
    const bootScreenEl = document.getElementById('bootScreen');
    const rawEditor = document.getElementById('raw_editor');
    const skipLinkEl = document.getElementById('skipLink');
    const appShellEl = document.getElementById('appShell');
    const authGateEl = document.getElementById('authGate');
    const authTitleEl = document.getElementById('authTitle');
    const authDescEl = document.getElementById('authDesc');
    const loginTokenLabelEl = document.getElementById('loginTokenLabel');
    const loginConfirmFieldEl = document.getElementById('loginConfirmField');
    const loginTokenInput = document.getElementById('login_token');
    const loginTokenConfirmInput = document.getElementById('login_token_confirm');
    const loginRememberEl = document.getElementById('login_remember');
    const loginBtn = document.getElementById('loginBtn');
    const loginHintEl = document.getElementById('loginHint');
    const logoutBtn = document.getElementById('logoutBtn');
    const openAdvancedBtn = document.getElementById('openAdvancedBtn');
    const backVisualBtn = document.getElementById('backVisualBtn');
    const tocLinks = Array.prototype.slice.call(document.querySelectorAll('.toc a'));
    const topbarEl = document.querySelector('.topbar');
    const tabVisual = document.getElementById('tabVisual');
    const tabRaw = document.getElementById('tabRaw');
    const primaryButtons = ['reloadBtn', 'saveBtn', 'saveRawBtn'];
    const inlineValidateTargets = ['monitor_interval', 'monitor_cpu_window', 'threshold_cpu', 'threshold_memory', 'threshold_disk', 'web_rate_limit'];
    let isDirty = false;
    let authMode = 'login';
    let hasAuthToken = false;

    function setBusy(busy) {
      primaryButtons.forEach(function(id) {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = busy;
      });
    }

    function setStatus(text, type) {
      const tone = type || 'idle';
      const content = (text || '').trim();
      if (tone === 'idle' && !content) {
        statusEl.textContent = '';
        statusEl.setAttribute('data-tone', 'idle');
        statusEl.classList.add('hidden');
        return;
      }
      statusEl.classList.remove('hidden');
      statusEl.textContent = content;
      statusEl.setAttribute('data-tone', tone);
    }

    function el(id) { return document.getElementById(id); }

    function setAuthHint(text) {
      if (loginHintEl) loginHintEl.textContent = text || '';
    }

    function hideBootScreen() {
      if (bootScreenEl) bootScreenEl.classList.add('hidden');
    }

    function setAuthMode(mode) {
      authMode = mode === 'setup' ? 'setup' : 'login';
      const isSetupFlow = authMode === 'setup';
      if (isSetupFlow) {
        if (authTitleEl) authTitleEl.textContent = '首次启动：设置访问口令';
        if (authDescEl) authDescEl.textContent = '检测到控制台仍使用默认占位口令，请先设置新的访问口令后再进入。';
        if (loginTokenLabelEl) loginTokenLabelEl.textContent = '新访问口令';
        if (loginBtn) loginBtn.textContent = '设置并进入主页';
        if (loginConfirmFieldEl) loginConfirmFieldEl.classList.remove('hidden');
      } else {
        if (authTitleEl) authTitleEl.textContent = '登录资源哨兵控制台';
        if (authDescEl) authDescEl.textContent = '当服务器开启鉴权时，需要先验证访问口令。若未开启鉴权，将自动进入主页。';
        if (loginTokenLabelEl) loginTokenLabelEl.textContent = '访问口令';
        if (loginBtn) loginBtn.textContent = '进入主页';
        if (loginConfirmFieldEl) loginConfirmFieldEl.classList.add('hidden');
      }
    }

    function showAuthGate(message) {
      hideBootScreen();
      if (appShellEl) appShellEl.classList.add('hidden');
      if (skipLinkEl) skipLinkEl.classList.add('hidden');
      if (authGateEl) authGateEl.classList.remove('hidden');
      if (message) setAuthHint(message);
    }

    function showAppShell() {
      hideBootScreen();
      if (authGateEl) authGateEl.classList.add('hidden');
      if (appShellEl) appShellEl.classList.remove('hidden');
      if (skipLinkEl) skipLinkEl.classList.remove('hidden');
      requestAnimationFrame(syncAnchorOffset);
    }

    async function fetchSetupStatus() {
      const result = await apiFetch('/api/setup/status');
      if (!result.res.ok) return { ok: false, required: false, error: result.data.error || '检查初始化状态失败' };
      return { ok: true, required: !!result.data.required };
    }

    async function fetchAuthStatus() {
      const result = await apiFetch('/api/auth/status');
      if (!result.res.ok) {
        return { ok: false, setupRequired: false, authenticated: false, error: result.data.error || '检查登录状态失败' };
      }
      return {
        ok: true,
        setupRequired: !!result.data.setup_required,
        authenticated: !!result.data.authenticated
      };
    }

    function safeText(id, text) {
      const node = el(id);
      if (node) node.textContent = text;
    }

    function formatPercent(value) {
      const num = Number(value);
      if (!Number.isFinite(num)) return '-';
      return String(Math.round(num * 10) / 10) + '%';
    }

    function updateOverview(payload) {
      if (!payload || !payload.monitor || !payload.notify || !payload.web) return;

      safeText(
        'ov_thresholds',
        'CPU ≥ ' + formatPercent(payload.monitor.thresholds.cpu) +
        ' / 内存 ≥ ' + formatPercent(payload.monitor.thresholds.memory) +
        ' / 磁盘 ≥ ' + formatPercent(payload.monitor.thresholds.disk)
      );

      const enabledChannels = [
        payload.notify.telegram && payload.notify.telegram.enabled,
        payload.notify.wechat && payload.notify.wechat.enabled,
        payload.notify.iyuu && payload.notify.iyuu.enabled,
        payload.notify.webhook && payload.notify.webhook.enabled,
        payload.notify.pushplus && payload.notify.pushplus.enabled
      ].filter(Boolean).length;
      safeText('ov_channels', enabledChannels + '/5 已启用');

      if (!payload.web.enabled) {
        safeText('ov_web_scope', '控制台已关闭');
      } else {
        const listen = (payload.web.listen || '').trim();
        const isPublicListen = listen && listen.indexOf('127.0.0.1') !== 0 && listen.indexOf('localhost') !== 0;
        safeText('ov_web_scope', isPublicListen ? '公网监听: ' + listen : '本地监听: ' + (listen || ':8080'));
      }

      safeText('ov_rate_limit', (payload.web.rate_limit_per_minute || 0) + ' req/min/IP');

      const risks = [];
      if (enabledChannels === 0) risks.push('未启用任何通知通道');
      if (payload.web.enabled) {
        const listen = (payload.web.listen || '').trim();
        const isPublicListen = listen && listen.indexOf('127.0.0.1') !== 0 && listen.indexOf('localhost') !== 0;
        const hasTokenValue = !!((payload.web.auth_token || '').trim());
        const hasToken = hasTokenValue || payload.web.has_auth_token === true || hasAuthToken;
        if (isPublicListen && !hasToken) risks.push('公网监听未配置访问口令');
        if (isPublicListen && (!payload.web.allowed_cidrs || payload.web.allowed_cidrs.length === 0)) risks.push('公网监听未设置 IP 白名单');
      }

      const riskNode = el('ov_risk');
      if (!riskNode) return;
      if (risks.length === 0) {
        riskNode.setAttribute('data-tone', 'ok');
        riskNode.textContent = '当前配置未发现显著风险，建议保存后重启服务验证生效状态。';
      } else {
        riskNode.setAttribute('data-tone', 'warn');
        riskNode.textContent = '注意：' + risks.join('；') + '。';
      }
    }

    function markDirty() {
      isDirty = true;
      setStatus('有未保存修改', 'warn');
      updateOverview(collectVisual());
    }

    function clearDirty() {
      isDirty = false;
    }

    function setTokenInputs(token) {
      const value = token || '';
      if (loginTokenInput) loginTokenInput.value = value;
    }

    function clearTokenInputs() {
      setTokenInputs('');
      if (loginTokenConfirmInput) loginTokenConfirmInput.value = '';
    }

    async function loginRequest(token, remember) {
      return await apiFetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, remember: !!remember })
      });
    }

    async function logoutRequest() {
      return await apiFetch('/api/auth/logout', {
        method: 'POST'
      });
    }

    async function logoutAndReset() {
      await logoutRequest();
      clearTokenInputs();
      if (loginRememberEl) loginRememberEl.checked = false;
      setAuthMode('login');
      showAuthGate('会话已失效，请重新登录。');
      setStatus('已退出登录', 'warn');
    }

    function tokenStrengthError(token) {
      if (!token) return '请先输入访问口令。';
      if (token.length < 8) return '访问口令至少需要 8 个字符。';
      if (token === 'CHANGE_ME_STRONG_TOKEN') return '不能使用默认占位口令。';
      return '';
    }

    function isAuthTokenMaskedValue(value) {
      return value === '__KEEP_EXISTING__';
    }

    function normalizeAuthTokenField() {
      const node = el('web_auth_token');
      if (!node) return;
      const raw = (node.value || '').trim();
      if (!raw) return;
      if (isAuthTokenMaskedValue(raw)) node.value = '';
    }

    function setAuthTokenFieldPlaceholder() {
      const node = el('web_auth_token');
      if (!node) return;
      if (hasAuthToken) {
        node.value = '';
        node.placeholder = '已设置口令；留空表示保持不变，填写则更新';
      } else {
        node.value = '';
        node.placeholder = '请设置访问口令（至少 8 个字符）';
      }
    }

    function saveToken(token) {
      if (!token) {
        clearTokenInputs();
        return;
      }
      setTokenInputs(token);
    }

    async function apiFetch(url, options) {
      const headers = new Headers((options && options.headers) || {});
      const requestOptions = Object.assign({}, options || {}, { headers: headers, credentials: 'same-origin' });
      const res = await fetch(url, requestOptions);
      let data = {};
      try {
        data = await res.json();
      } catch (e) {}
      if (res.status === 401) setStatus('鉴权失败，请更新访问口令', 'err');
      return { res: res, data: data };
    }

    function syncAnchorOffset() {
      const fallback = 120;
      const topbarHeight = topbarEl ? Math.ceil(topbarEl.getBoundingClientRect().height) : 0;
      const offset = Math.max(fallback, topbarHeight + 24);
      document.documentElement.style.setProperty('--anchor-offset', String(offset) + 'px');
      return offset;
    }

    function scrollToHash(hash) {
      const target = document.querySelector(hash);
      if (!target) return;
      const offset = syncAnchorOffset();
      const top = target.getBoundingClientRect().top + window.scrollY - offset;
      window.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
    }

    function switchTab(toRaw) {
      tabVisual.classList.toggle('active', !toRaw);
      tabRaw.classList.toggle('active', toRaw);
      const saveVisualBtn = document.getElementById('saveBtn');
      if (saveVisualBtn) saveVisualBtn.classList.toggle('hidden', toRaw);
      if (openAdvancedBtn) openAdvancedBtn.classList.toggle('hidden', toRaw);
      syncAnchorOffset();
    }

    function fillVisual(cfg) {
      el('monitor_interval').value = cfg.monitor.interval || '';
      el('monitor_cpu_window').value = cfg.monitor.cpu_window || '';
      el('monitor_disk_path').value = cfg.monitor.disk_path || '';
      el('monitor_consecutive').value = cfg.monitor.consecutive || 1;
      el('threshold_cpu').value = cfg.monitor.thresholds.cpu;
      el('threshold_memory').value = cfg.monitor.thresholds.memory;
      el('threshold_disk').value = cfg.monitor.thresholds.disk;
      el('tg_enabled').checked = !!cfg.notify.telegram.enabled;
      el('network_proxy_url').value = (cfg.network && cfg.network.proxy_url) || '';
      el('tg_token').value = cfg.notify.telegram.token || '';
      el('tg_chat_id').value = cfg.notify.telegram.chat_id || '';
      el('tg_api_base').value = cfg.notify.telegram.api_base || '';
      el('wechat_enabled').checked = !!cfg.notify.wechat.enabled;
      el('wechat_webhook').value = cfg.notify.wechat.webhook || '';
      el('iyuu_enabled').checked = !!cfg.notify.iyuu.enabled;
      el('iyuu_token').value = cfg.notify.iyuu.token || '';
      el('webhook_enabled').checked = !!cfg.notify.webhook.enabled;
      el('webhook_url').value = cfg.notify.webhook.url || '';
      el('pushplus_enabled').checked = !!cfg.notify.pushplus.enabled;
      el('pushplus_token').value = cfg.notify.pushplus.token || '';
      el('pushplus_template').value = cfg.notify.pushplus.template || 'txt';
      el('pushplus_topic').value = cfg.notify.pushplus.topic || '';
      el('web_listen').value = cfg.web.listen || '127.0.0.1:8080';
      hasAuthToken = !!cfg.web.has_auth_token;
      setAuthTokenFieldPlaceholder();
      el('web_allowed_cidrs').value = (cfg.web.allowed_cidrs || []).join(',');
      el('web_rate_limit').value = cfg.web.rate_limit_per_minute || 120;
      updateOverview(cfg);
    }

    function collectVisual() {
      return {
        monitor: {
          interval: el('monitor_interval').value.trim(),
          cpu_window: el('monitor_cpu_window').value.trim(),
          disk_path: el('monitor_disk_path').value.trim(),
          consecutive: Number(el('monitor_consecutive').value || 1),
          thresholds: {
            cpu: Number(el('threshold_cpu').value),
            memory: Number(el('threshold_memory').value),
            disk: Number(el('threshold_disk').value)
          }
        },
        network: {
          proxy_url: el('network_proxy_url').value.trim()
        },
        notify: {
          telegram: {
            enabled: el('tg_enabled').checked,
            token: el('tg_token').value.trim(),
            chat_id: el('tg_chat_id').value.trim(),
            api_base: el('tg_api_base').value.trim()
          },
          wechat: { enabled: el('wechat_enabled').checked, webhook: el('wechat_webhook').value.trim() },
          iyuu: { enabled: el('iyuu_enabled').checked, token: el('iyuu_token').value.trim() },
          webhook: { enabled: el('webhook_enabled').checked, url: el('webhook_url').value.trim() },
          pushplus: {
            enabled: el('pushplus_enabled').checked,
            token: el('pushplus_token').value.trim(),
            template: el('pushplus_template').value,
            topic: el('pushplus_topic').value.trim()
          }
        },
        web: {
          enabled: true,
          listen: el('web_listen').value.trim(),
          auth_token: el('web_auth_token').value.trim(),
          allowed_cidrs: el('web_allowed_cidrs').value.split(',').map(function(v){ return v.trim(); }).filter(Boolean),
          rate_limit_per_minute: Number(el('web_rate_limit').value || 120)
        }
      };
    }

    function clearValidationStates() {
      ['monitor_interval', 'monitor_cpu_window', 'threshold_cpu', 'threshold_memory', 'threshold_disk', 'web_rate_limit', 'web_auth_token'].forEach(function(id){
        el(id).classList.remove('error');
      });
    }

    function validateVisualPayload(payload) {
      clearValidationStates();
      let ok = true;
      function invalidate(id) { el(id).classList.add('error'); ok = false; }
      normalizeAuthTokenField();
      if (!payload.monitor.interval) invalidate('monitor_interval');
      if (!payload.monitor.cpu_window) invalidate('monitor_cpu_window');
      if (payload.monitor.thresholds.cpu <= 0 || payload.monitor.thresholds.cpu > 100) invalidate('threshold_cpu');
      if (payload.monitor.thresholds.memory <= 0 || payload.monitor.thresholds.memory > 100) invalidate('threshold_memory');
      if (payload.monitor.thresholds.disk <= 0 || payload.monitor.thresholds.disk > 100) invalidate('threshold_disk');
      if (!payload.web.rate_limit_per_minute || payload.web.rate_limit_per_minute < 1) invalidate('web_rate_limit');
      const publicListen = payload.web.enabled && payload.web.listen && payload.web.listen.indexOf('127.0.0.1') !== 0 && payload.web.listen.indexOf('localhost') !== 0;
      const newToken = (payload.web.auth_token || '').trim();
      if (newToken) {
        const tokenErr = tokenStrengthError(newToken);
        if (tokenErr) invalidate('web_auth_token');
      }
      if (publicListen && !hasAuthToken && !newToken) invalidate('web_auth_token');
      if (!ok) setStatus('请先修正红框字段', 'err');
      return ok;
    }

    function validateSingleField(id) {
      const payload = collectVisual();
      validateVisualPayload(payload);
      if (!el(id).classList.contains('error')) return true;
      return false;
    }

    async function loadVisual(options) {
      const silentUnauthorized = !!(options && options.silentUnauthorized);
      setBusy(true);
      setStatus('加载中...', 'idle');
      const result = await apiFetch('/api/config');
      if (result.res.status === 401) {
        setBusy(false);
        if (!silentUnauthorized) setStatus('鉴权失败，请更新访问口令', 'err');
        return 'unauthorized';
      }
      if (result.res.status === 403 && result.data && result.data.error === 'initial setup required') {
        setBusy(false);
        return 'setup-required';
      }
      if (!result.res.ok) {
        setBusy(false);
        setStatus(result.data.error || '加载失败', 'err');
        return 'error';
      }
      fillVisual(result.data);
      clearValidationStates();
      clearDirty();
      setBusy(false);
      setStatus('已加载最新配置', 'ok');
      return 'ok';
    }

    async function saveVisual() {
      const payload = collectVisual();
      if (!validateVisualPayload(payload)) return;
      setBusy(true);
      setStatus('保存中...', 'idle');
      const result = await apiFetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!result.res.ok) {
        setBusy(false);
        if (result.res.status === 401) {
          await logoutAndReset();
          return;
        }
        setStatus(result.data.error || '保存失败', 'err');
        return;
      }
      await loadRaw();
      if ((payload.web.auth_token || '').trim()) {
        hasAuthToken = true;
        setAuthTokenFieldPlaceholder();
      }
      clearDirty();
      setBusy(false);
      setStatus(result.data.message || '保存成功', 'ok');
    }

    async function loadRaw() {
      const result = await apiFetch('/api/config/raw');
      if (result.res.ok) {
        rawEditor.value = result.data.content || '';
        return;
      }
      if (result.res.status === 401) await logoutAndReset();
    }

    async function saveRaw() {
      setBusy(true);
      setStatus('保存 YAML 中...', 'idle');
      const result = await apiFetch('/api/config/raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: rawEditor.value })
      });
      if (!result.res.ok) {
        setBusy(false);
        if (result.res.status === 401) {
          await logoutAndReset();
          return;
        }
        setStatus(result.data.error || '保存失败', 'err');
        return;
      }
      await loadVisual();
      clearDirty();
      setBusy(false);
      setStatus(result.data.message || '保存成功', 'ok');
    }

    function bindDirtyWatchers() {
      document.querySelectorAll('#main input,#main select,#main textarea').forEach(function(node) {
        node.addEventListener('input', markDirty);
        node.addEventListener('change', markDirty);
      });

      inlineValidateTargets.forEach(function(id) {
        const node = el(id);
        if (!node) return;
        node.addEventListener('blur', function() {
          validateSingleField(id);
        });
      });
    }

    function setupToken() {
      const urlToken = new URLSearchParams(window.location.search).get('token');
      if (urlToken) {
        setTokenInputs(urlToken.trim());
      } else {
        clearTokenInputs();
      }
      if (loginRememberEl) loginRememberEl.checked = false;
    }

    async function loginWithToken() {
      const token = (loginTokenInput && loginTokenInput.value || '').trim();
      const tokenErr = tokenStrengthError(token);
      if (tokenErr) {
        showAuthGate(tokenErr);
        return;
      }

      const remember = !!(loginRememberEl && loginRememberEl.checked);
      saveToken(token);
      const isSetupFlow = authMode === 'setup';

      if (isSetupFlow) {
        const confirm = (loginTokenConfirmInput && loginTokenConfirmInput.value || '').trim();
        if (confirm != token) {
          showAuthGate('两次输入的访问口令不一致，请重新输入。');
          return;
        }

        setAuthHint('初始化中...');
        const setupResult = await apiFetch('/api/setup/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token, remember: remember })
        });
        if (!setupResult.res.ok) {
          if (setupResult.res.status === 409) {
            setAuthMode('login');
            showAuthGate('初始化已完成，请使用口令登录。');
            return;
          }
          showAuthGate(setupResult.data.error || '初始化失败，请稍后重试。');
          return;
        }
        setAuthHint('初始化成功，正在进入控制台...');
      } else {
        setAuthHint('验证中...');
        const loginResult = await loginRequest(token, remember);
        if (!loginResult.res.ok) {
          showAuthGate(loginResult.data.error || '访问口令错误，请重试。');
          setStatus('鉴权失败，请更新访问口令', 'err');
          return;
        }
      }

      const state = await loadVisual({ silentUnauthorized: true });
      if (state === 'ok') {
        showAppShell();
        await loadRaw();
        setStatus('', 'idle');
        setAuthHint('登录成功。');
        if (loginTokenConfirmInput) loginTokenConfirmInput.value = '';
        return;
      }
      if (state === 'setup-required') {
        setAuthMode('setup');
        showAuthGate('检测到仍处于首次启动状态，请先设置访问口令。');
        return;
      }
      if (state === 'unauthorized') {
        setAuthMode('login');
        showAuthGate('访问口令错误，请重试。');
        setStatus('鉴权失败，请更新访问口令', 'err');
        return;
      }
      showAuthGate('暂时无法连接控制台，请稍后重试。');
    }

    window.addEventListener('beforeunload', function(e) {
      if (!isDirty) return;
      e.preventDefault();
      e.returnValue = '';
    });

    if (openAdvancedBtn) openAdvancedBtn.addEventListener('click', function(){ switchTab(true); });
    if (backVisualBtn) backVisualBtn.addEventListener('click', function(){ switchTab(false); });
    window.addEventListener('resize', syncAnchorOffset);
    tocLinks.forEach(function(link) {
      link.addEventListener('click', function(e) {
        const href = (link.getAttribute('href') || '').trim();
        if (!href || href.charAt(0) !== '#') return;
        e.preventDefault();
        const toRaw = href === '#advanced';
        switchTab(toRaw);
        requestAnimationFrame(function() {
          scrollToHash(href);
        });
      });
    });
    document.getElementById('reloadBtn').addEventListener('click', async function() {
      const state = await loadVisual();
      if (state === 'unauthorized') {
        await logoutAndReset();
        return;
      }
      await loadRaw();
    });
    document.getElementById('saveBtn').addEventListener('click', saveVisual);
    document.getElementById('saveRawBtn').addEventListener('click', saveRaw);
    if (logoutBtn) logoutBtn.addEventListener('click', logoutAndReset);
    loginBtn.addEventListener('click', loginWithToken);
    if (loginTokenInput) {
      loginTokenInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') loginWithToken();
      });
    }

    (async function init() {
      setupToken();
      bindDirtyWatchers();
      syncAnchorOffset();
      switchTab(false);

      const authStatus = await fetchAuthStatus();
      if (authStatus.ok) {
        if (authStatus.setupRequired) {
          setAuthMode('setup');
          showAuthGate('首次启动请先设置访问口令。');
          return;
        }

        if (authStatus.authenticated) {
          setAuthMode('login');
          const state = await loadVisual({ silentUnauthorized: true });
          if (state === 'ok') {
            showAppShell();
            await loadRaw();
            setStatus('', 'idle');
            setAuthHint('已自动登录。');
            return;
          }
          if (state === 'setup-required') {
            setAuthMode('setup');
            showAuthGate('首次启动请先设置访问口令。');
            return;
          }
          if (state === 'unauthorized') {
            showAuthGate('请输入访问口令以登录控制台。');
            return;
          }
          showAuthGate('连接状态异常，可稍后重试。');
          return;
        }

        setAuthMode('login');
        showAuthGate('请输入访问口令以登录控制台。');
        return;
      }

      const setupStatus = await fetchSetupStatus();
      if (setupStatus.ok && setupStatus.required) {
        setAuthMode('setup');
        showAuthGate('首次启动请先设置访问口令。');
        return;
      }
      setAuthMode('login');
      const state = await loadVisual({ silentUnauthorized: true });
      if (state === 'ok') {
        showAppShell();
        await loadRaw();
        setStatus('', 'idle');
        setAuthHint('已自动登录。');
        return;
      }
      if (state === 'setup-required') {
        setAuthMode('setup');
        showAuthGate('首次启动请先设置访问口令。');
        return;
      }
      if (state === 'unauthorized') {
        showAuthGate('请输入访问口令以登录控制台。');
        return;
      }
      showAuthGate(setupStatus.ok ? '连接状态异常，可稍后重试。' : (setupStatus.error || '连接状态异常，可稍后重试。'));
    })();
  </script>
</body>
</html>`
