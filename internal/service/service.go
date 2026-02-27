package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"resource-sentinel/internal/monitor"
	"resource-sentinel/internal/notify"
)

type Runner struct {
	collector monitor.Collector
	evaluator *monitor.Evaluator
	notifier  *notify.MultiNotifier
	interval  time.Duration
	logger    *log.Logger
}

func NewRunner(
	collector monitor.Collector,
	evaluator *monitor.Evaluator,
	notifier *notify.MultiNotifier,
	interval time.Duration,
	logger *log.Logger,
) *Runner {
	if logger == nil {
		logger = log.Default()
	}
	return &Runner{
		collector: collector,
		evaluator: evaluator,
		notifier:  notifier,
		interval:  interval,
		logger:    logger,
	}
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.checkOnce(ctx); err != nil {
		r.logger.Printf("initial check failed: %v", err)
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.checkOnce(ctx); err != nil {
				r.logger.Printf("monitor check failed: %v", err)
			}
		}
	}
}

func (r *Runner) checkOnce(ctx context.Context) error {
	sample, err := r.collector.Collect(ctx)
	if err != nil {
		return err
	}

	events := r.evaluator.Evaluate(sample)
	for _, event := range events {
		message := formatMessage(event)
		r.logger.Printf("event=%s metric=%s usage=%.2f threshold=%.2f", event.Type, event.Metric, event.Usage, event.Threshold)
		if r.notifier != nil {
			if err := r.notifier.Send(ctx, message); err != nil {
				r.logger.Printf("send notification failed: %v", err)
			}
		}
	}

	return nil
}

func formatMessage(event monitor.Event) notify.Message {
	metricName := map[monitor.MetricType]string{
		monitor.MetricCPU:    "CPU",
		monitor.MetricMemory: "内存",
		monitor.MetricDisk:   "磁盘",
	}[event.Metric]
	if metricName == "" {
		metricName = strings.ToUpper(string(event.Metric))
	}

	title := "资源告警"
	if event.Type == monitor.EventRecover {
		title = "资源恢复"
	}

	body := fmt.Sprintf(
		"指标: %s\n当前值: %.2f%%\n阈值: %.2f%%\n时间: %s",
		metricName,
		event.Usage,
		event.Threshold,
		event.At.Format(time.RFC3339),
	)

	return notify.Message{
		Title: title,
		Body:  body,
	}
}
