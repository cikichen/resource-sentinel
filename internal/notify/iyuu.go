package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type IYUUNotifier struct {
	token   string
	baseURL string
	client  *http.Client
}

func NewIYUUNotifier(token string) *IYUUNotifier {
	return &IYUUNotifier{
		token:   strings.TrimSpace(token),
		baseURL: "https://iyuu.cn",
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *IYUUNotifier) Name() string {
	return "iyuu"
}

func (n *IYUUNotifier) Send(ctx context.Context, message Message) error {
	if n.token == "" {
		return fmt.Errorf("iyuu token is empty")
	}

	form := url.Values{
		"text": {message.Title},
		"desp": {message.Body},
	}

	sendURL := fmt.Sprintf("%s/%s.send", strings.TrimRight(n.baseURL, "/"), url.PathEscape(n.token))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create iyuu request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send iyuu request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("iyuu response status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
