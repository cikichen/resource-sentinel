package config

import "testing"

func TestValidateWebAuthRequiredOnPublicListen(t *testing.T) {
	cfg := Default()
	cfg.Web.Enabled = true
	cfg.Web.Listen = ":8080"
	cfg.Web.AuthToken = ""

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for public listen without auth token")
	}
}

func TestValidateWebLoopbackWithoutAuthAllowed(t *testing.T) {
	cfg := Default()
	cfg.Web.Enabled = true
	cfg.Web.Listen = "127.0.0.1:8080"
	cfg.Web.AuthToken = ""

	if err := Validate(cfg); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidateWebCIDRs(t *testing.T) {
	cfg := Default()
	cfg.Web.Enabled = true
	cfg.Web.Listen = "127.0.0.1:8080"
	cfg.Web.AllowedCIDRs = []string{"10.0.0.0/8", "bad-value"}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected invalid cidr error")
	}
}

func TestValidateNetworkProxyURL(t *testing.T) {
	cfg := Default()
	cfg.Network.ProxyURL = "http://127.0.0.1:7890"

	if err := Validate(cfg); err != nil {
		t.Fatalf("expected valid proxy_url, got %v", err)
	}
}

func TestValidateNetworkProxyURLInvalid(t *testing.T) {
	cfg := Default()
	cfg.Network.ProxyURL = "ftp://127.0.0.1:21"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected invalid proxy_url error")
	}
}
