package notify

import (
	"context"
	"errors"
	"fmt"
)

type Message struct {
	Title string
	Body  string
}

type Notifier interface {
	Name() string
	Send(ctx context.Context, message Message) error
}

type MultiNotifier struct {
	notifiers []Notifier
}

func NewMultiNotifier(notifiers ...Notifier) *MultiNotifier {
	return &MultiNotifier{notifiers: notifiers}
}

func (m *MultiNotifier) Send(ctx context.Context, message Message) error {
	var errs []error
	for _, notifier := range m.notifiers {
		if err := notifier.Send(ctx, message); err != nil {
			errs = append(errs, fmt.Errorf("%s notify failed: %w", notifier.Name(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
