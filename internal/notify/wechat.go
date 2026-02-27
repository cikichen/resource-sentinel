package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type WeChatNotifier struct {
	webhook string
	client  *http.Client
}

func NewWeChatNotifier(webhook string) *WeChatNotifier {
	return &WeChatNotifier{
		webhook: strings.TrimSpace(webhook),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *WeChatNotifier) Name() string {
	return "wechat"
}

func (n *WeChatNotifier) Send(ctx context.Context, message Message) error {
	if n.webhook == "" {
		return fmt.Errorf("wechat webhook is empty")
	}

	payload := map[string]any{
		"msgtype": "text",
		"text": map[string]string{
			"content": fmt.Sprintf("%s\n%s", message.Title, message.Body),
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal wechat payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhook, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create wechat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send wechat request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("wechat response status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
