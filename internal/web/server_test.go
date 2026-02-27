package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfigYAML = `monitor:
  interval: 15s
  cpu_window: 1s
  disk_path: "/"
  consecutive: 3
  thresholds:
    cpu: 85
    memory: 80
    disk: 90

notify:
  telegram:
    enabled: false
    token: ""
    chat_id: ""
  wechat:
    enabled: false
    webhook: ""
  iyuu:
    enabled: false
    token: ""
  webhook:
    enabled: false
    url: ""
  pushplus:
    enabled: false
    token: ""
    template: "txt"
    topic: ""
`

func TestGetRawConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, "")
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "monitor:") {
		t.Fatalf("unexpected response: %s", rr.Body.String())
	}
}

func TestSaveRawConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, "")
	payload := map[string]string{"content": strings.ReplaceAll(testConfigYAML, "cpu: 85", "cpu: 70")}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/config/raw", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rr.Code, rr.Body.String())
	}

	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read saved config failed: %v", err)
	}
	if !strings.Contains(string(saved), "cpu: 70") {
		t.Fatalf("config not updated, content=%s", string(saved))
	}
}

func TestSaveRawConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, "")
	badConfig := strings.ReplaceAll(testConfigYAML, "cpu: 85", "cpu: 1000")
	payload := map[string]string{"content": badConfig}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/config/raw", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestAuthTokenRequired(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, "secret-token")
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestGetVisualConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, "")
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rr.Code, rr.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	monitor, ok := got["monitor"].(map[string]any)
	if !ok {
		t.Fatalf("monitor section missing: %v", got)
	}
	if monitor["interval"] != "15s" {
		t.Fatalf("unexpected interval: %v", monitor["interval"])
	}
}

func TestSaveVisualConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, "")
	payload := map[string]any{
		"monitor": map[string]any{
			"interval":    "10s",
			"cpu_window":  "1s",
			"disk_path":   "/",
			"consecutive": 2,
			"thresholds": map[string]any{
				"cpu":    66.0,
				"memory": 77.0,
				"disk":   88.0,
			},
		},
		"notify": map[string]any{
			"telegram": map[string]any{"enabled": false, "token": "", "chat_id": ""},
			"wechat":   map[string]any{"enabled": false, "webhook": ""},
			"iyuu":     map[string]any{"enabled": false, "token": ""},
			"webhook":  map[string]any{"enabled": false, "url": ""},
			"pushplus": map[string]any{"enabled": false, "token": "", "template": "txt", "topic": ""},
		},
		"web": map[string]any{
			"enabled":               true,
			"listen":                ":8080",
			"auth_token":            "abc12345",
			"allowed_cidrs":         []string{},
			"rate_limit_per_minute": 120,
		},
	}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rr.Code, rr.Body.String())
	}

	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read saved config failed: %v", err)
	}
	content := string(saved)
	if !strings.Contains(content, "cpu: 66") {
		t.Fatalf("cpu threshold not updated: %s", content)
	}
	if !strings.Contains(content, "interval: 10s") {
		t.Fatalf("interval not updated: %s", content)
	}
	if !strings.Contains(content, "auth_token: $2") {
		t.Fatalf("web auth token should be bcrypt hash: %s", content)
	}
	if strings.Contains(content, "abc12345") {
		t.Fatalf("plaintext auth token should not be persisted: %s", content)
	}
}

func TestAllowedCIDRRejectsClient(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandlerWithOptions(configPath, "", []string{"10.0.0.0/8"}, 120)
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestRateLimit(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandlerWithOptions(configPath, "", nil, 1)

	req1 := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", rr2.Code)
	}
}

func TestSetupStatusRequiredWhenUsingBootstrapToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, bootstrapAuthToken)
	req := httptest.NewRequest(http.MethodGet, "/api/setup/status", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"required":true`) {
		t.Fatalf("expected required=true, got body=%s", rr.Body.String())
	}

	configReq := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	configResp := httptest.NewRecorder()
	h.ServeHTTP(configResp, configReq)
	if configResp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 before setup, got %d, body=%s", configResp.Code, configResp.Body.String())
	}
}

func TestSetupAuthAppliesTokenImmediately(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, bootstrapAuthToken)
	setupPayload := map[string]string{"token": "new-strong-token-123"}
	setupBody, _ := json.Marshal(setupPayload)
	setupReq := httptest.NewRequest(http.MethodPost, "/api/setup/auth", bytes.NewReader(setupBody))
	setupReq.Header.Set("Content-Type", "application/json")
	setupResp := httptest.NewRecorder()
	h.ServeHTTP(setupResp, setupReq)
	if setupResp.Code != http.StatusOK {
		t.Fatalf("expected setup 200, got %d, body=%s", setupResp.Code, setupResp.Body.String())
	}

	configReqNoToken := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	configRespNoToken := httptest.NewRecorder()
	h.ServeHTTP(configRespNoToken, configReqNoToken)
	if configRespNoToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after setup without token, got %d, body=%s", configRespNoToken.Code, configRespNoToken.Body.String())
	}

	configReqWithLegacyHeader := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	configReqWithLegacyHeader.Header.Set("X-Config-Token", "new-strong-token-123")
	configRespWithLegacyHeader := httptest.NewRecorder()
	h.ServeHTTP(configRespWithLegacyHeader, configReqWithLegacyHeader)
	if configRespWithLegacyHeader.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with legacy header auth, got %d, body=%s", configRespWithLegacyHeader.Code, configRespWithLegacyHeader.Body.String())
	}

	loginCookie := setupResp.Result().Cookies()
	if len(loginCookie) == 0 {
		t.Fatalf("expected setup response to set session cookie")
	}

	configReqWithSession := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	configReqWithSession.AddCookie(loginCookie[0])
	configRespWithSession := httptest.NewRecorder()
	h.ServeHTTP(configRespWithSession, configReqWithSession)
	if configRespWithSession.Code != http.StatusOK {
		t.Fatalf("expected 200 with session cookie, got %d, body=%s", configRespWithSession.Code, configRespWithSession.Body.String())
	}

	saved, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read saved config failed: %v", err)
	}
	savedText := string(saved)
	if !strings.Contains(savedText, "auth_token: $2") {
		t.Fatalf("expected saved bcrypt auth token, got %s", savedText)
	}
	if strings.Contains(savedText, "new-strong-token-123") {
		t.Fatalf("plaintext auth token should not be persisted, got %s", savedText)
	}
}

func TestRuntimeRequiresInitialSetup(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testConfigYAML), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, bootstrapAuthToken)
	req := httptest.NewRequest(http.MethodGet, "/api/runtime", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 before setup, got %d, body=%s", rr.Code, rr.Body.String())
	}
}

func TestRuntimeReturnsSampleAfterLogin(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := strings.Replace(testConfigYAML, "cpu_window: 1s", "cpu_window: 10ms", 1)
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write test config failed: %v", err)
	}

	h := NewHandler(configPath, bootstrapAuthToken)
	setupPayload := map[string]string{"token": "new-strong-token-123"}
	setupBody, _ := json.Marshal(setupPayload)
	setupReq := httptest.NewRequest(http.MethodPost, "/api/setup/auth", bytes.NewReader(setupBody))
	setupReq.Header.Set("Content-Type", "application/json")
	setupResp := httptest.NewRecorder()
	h.ServeHTTP(setupResp, setupReq)
	if setupResp.Code != http.StatusOK {
		t.Fatalf("expected setup 200, got %d, body=%s", setupResp.Code, setupResp.Body.String())
	}

	runtimeNoSessionReq := httptest.NewRequest(http.MethodGet, "/api/runtime", nil)
	runtimeNoSessionResp := httptest.NewRecorder()
	h.ServeHTTP(runtimeNoSessionResp, runtimeNoSessionReq)
	if runtimeNoSessionResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d, body=%s", runtimeNoSessionResp.Code, runtimeNoSessionResp.Body.String())
	}

	cookies := setupResp.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie from setup response")
	}
	runtimeReq := httptest.NewRequest(http.MethodGet, "/api/runtime", nil)
	runtimeReq.AddCookie(cookies[0])
	runtimeResp := httptest.NewRecorder()
	h.ServeHTTP(runtimeResp, runtimeReq)
	if runtimeResp.Code != http.StatusOK {
		t.Fatalf("expected runtime 200, got %d, body=%s", runtimeResp.Code, runtimeResp.Body.String())
	}
	if !strings.Contains(runtimeResp.Body.String(), `"sample"`) {
		t.Fatalf("expected runtime sample payload, got %s", runtimeResp.Body.String())
	}
}
