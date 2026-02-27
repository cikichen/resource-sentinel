package notify

import (
	"net/http"
	"net/url"
	"testing"
)

func TestNewHTTPClientWithProxy(t *testing.T) {
	client := newHTTPClient("http://127.0.0.1:7890")
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type mismatch: %T", client.Transport)
	}
	if transport.Proxy == nil {
		t.Fatal("proxy func should not be nil")
	}
	reqURL, _ := url.Parse("https://example.com")
	req := &http.Request{URL: reqURL}
	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy resolve failed: %v", err)
	}
	if got == nil || got.String() != "http://127.0.0.1:7890" {
		t.Fatalf("unexpected proxy url: %v", got)
	}
}
