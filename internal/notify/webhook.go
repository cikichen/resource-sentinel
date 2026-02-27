package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type WebhookNotifier struct {
	url    string
	client *http.Client
}

func NewWebhookNotifier(webhookURL, proxyURL string) *WebhookNotifier {
	return &WebhookNotifier{
		url:    strings.TrimSpace(webhookURL),
		client: newHTTPClient(proxyURL),
	}
}

func (n *WebhookNotifier) Name() string {
	return "webhook"
}

func (n *WebhookNotifier) Send(ctx context.Context, message Message) error {
	if n.url == "" {
		return fmt.Errorf("webhook url is empty")
	}

	payload := map[string]string{
		"title": message.Title,
		"body":  message.Body,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook response status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
