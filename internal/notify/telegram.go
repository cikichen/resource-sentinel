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

type TelegramNotifier struct {
	token  string
	chatID string
	client *http.Client
}

func NewTelegramNotifier(token, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		token:  strings.TrimSpace(token),
		chatID: strings.TrimSpace(chatID),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *TelegramNotifier) Name() string {
	return "telegram"
}

func (n *TelegramNotifier) Send(ctx context.Context, message Message) error {
	if n.token == "" || n.chatID == "" {
		return fmt.Errorf("telegram token/chat_id is empty")
	}

	payload := map[string]string{
		"chat_id":    n.chatID,
		"text":       fmt.Sprintf("%s\n%s", message.Title, message.Body),
		"parse_mode": "HTML",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("telegram response status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
