package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestIYUUNotifierSend(t *testing.T) {
	var gotPath string
	var gotValues url.Values

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body failed: %v", err)
		}
		_ = r.Body.Close()

		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse query failed: %v", err)
		}
		gotValues = values

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"msg":"请求成功"}`))
	}))
	defer server.Close()

	n := NewIYUUNotifier("token-123")
	n.baseURL = server.URL
	n.client = server.Client()

	message := Message{Title: "资源告警", Body: "CPU 超阈值"}
	if err := n.Send(context.Background(), message); err != nil {
		t.Fatalf("send iyuu message failed: %v", err)
	}

	if gotPath != "/token-123.send" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotValues.Get("text") != "资源告警" {
		t.Fatalf("unexpected text value: %s", gotValues.Get("text"))
	}
	if gotValues.Get("desp") != "CPU 超阈值" {
		t.Fatalf("unexpected desp value: %s", gotValues.Get("desp"))
	}
}

func TestWebhookNotifierSend(t *testing.T) {
	var got map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("unexpected content type: %s", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body failed: %v", err)
		}
		_ = r.Body.Close()

		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal payload failed: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"msg":"请求成功"}`))
	}))
	defer server.Close()

	n := NewWebhookNotifier(server.URL)
	n.client = server.Client()

	message := Message{Title: "资源恢复", Body: "CPU 已恢复"}
	if err := n.Send(context.Background(), message); err != nil {
		t.Fatalf("send webhook message failed: %v", err)
	}

	if got["title"] != "资源恢复" {
		t.Fatalf("unexpected title: %s", got["title"])
	}
	if got["body"] != "CPU 已恢复" {
		t.Fatalf("unexpected body: %s", got["body"])
	}
}

func TestPushPlusNotifierSend(t *testing.T) {
	var got map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("unexpected content type: %s", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body failed: %v", err)
		}
		_ = r.Body.Close()

		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("unmarshal payload failed: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"msg":"请求成功"}`))
	}))
	defer server.Close()

	n := NewPushPlusNotifier("push-token")
	n.baseURL = server.URL
	n.client = server.Client()
	n.template = "markdown"
	n.topic = "ops-group"

	message := Message{Title: "资源告警", Body: "内存占用过高"}
	if err := n.Send(context.Background(), message); err != nil {
		t.Fatalf("send pushplus message failed: %v", err)
	}

	if got["token"] != "push-token" {
		t.Fatalf("unexpected token: %v", got["token"])
	}
	if got["title"] != "资源告警" {
		t.Fatalf("unexpected title: %v", got["title"])
	}
	if got["content"] != "内存占用过高" {
		t.Fatalf("unexpected content: %v", got["content"])
	}
	if got["template"] != "markdown" {
		t.Fatalf("unexpected template: %v", got["template"])
	}
	if got["topic"] != "ops-group" {
		t.Fatalf("unexpected topic: %v", got["topic"])
	}
}

func TestPushPlusNotifierSend_BusinessError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":905,"msg":"账户未进行实名认证"}`))
	}))
	defer server.Close()

	n := NewPushPlusNotifier("push-token")
	n.baseURL = server.URL
	n.client = server.Client()

	err := n.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err == nil {
		t.Fatal("expected error when pushplus returns non-success code")
	}
	if !strings.Contains(err.Error(), "code=905") {
		t.Fatalf("unexpected error: %v", err)
	}
}
