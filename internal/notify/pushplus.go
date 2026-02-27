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

type PushPlusNotifier struct {
	token    string
	template string
	topic    string
	baseURL  string
	client   *http.Client
}

func NewPushPlusNotifier(token string) *PushPlusNotifier {
	return &PushPlusNotifier{
		token:    strings.TrimSpace(token),
		template: "txt",
		baseURL:  "https://www.pushplus.plus/send",
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *PushPlusNotifier) WithTemplate(template string) *PushPlusNotifier {
	if strings.TrimSpace(template) != "" {
		n.template = strings.TrimSpace(template)
	}
	return n
}

func (n *PushPlusNotifier) WithTopic(topic string) *PushPlusNotifier {
	n.topic = strings.TrimSpace(topic)
	return n
}

func (n *PushPlusNotifier) Name() string {
	return "pushplus"
}

func (n *PushPlusNotifier) Send(ctx context.Context, message Message) error {
	if n.token == "" {
		return fmt.Errorf("pushplus token is empty")
	}

	payload := map[string]string{
		"token":    n.token,
		"title":    message.Title,
		"content":  message.Body,
		"template": n.template,
	}
	if n.topic != "" {
		payload["topic"] = n.topic
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal pushplus payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.baseURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create pushplus request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send pushplus request: %w", err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return fmt.Errorf("read pushplus response body: %w", readErr)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("pushplus response status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse pushplus response: %w", err)
	}
	if result.Code != 200 {
		return fmt.Errorf("pushplus business error code=%d msg=%s", result.Code, result.Msg)
	}

	return nil
}
