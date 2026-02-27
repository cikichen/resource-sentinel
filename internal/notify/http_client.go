package notify

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

func newHTTPClient(proxyURL string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	cleanProxy := strings.TrimSpace(proxyURL)
	if cleanProxy != "" {
		if parsed, err := url.Parse(cleanProxy); err == nil {
			transport.Proxy = http.ProxyURL(parsed)
		}
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}
