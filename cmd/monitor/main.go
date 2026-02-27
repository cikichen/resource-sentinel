package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"resource-sentinel/internal/config"
	"resource-sentinel/internal/monitor"
	"resource-sentinel/internal/notify"
	"resource-sentinel/internal/service"
	"resource-sentinel/internal/web"
)

func main() {
	defaultPath := os.Getenv("CONFIG_PATH")
	if defaultPath == "" {
		defaultPath = "configs/config.yaml"
	}

	configPath := flag.String("config", defaultPath, "path to config yaml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	collector := monitor.NewSystemCollector(cfg.Monitor.DiskPath, cfg.Monitor.CPUWindow)
	evaluator := monitor.NewEvaluator(monitor.Thresholds{
		CPU:         cfg.Monitor.Thresholds.CPU,
		Memory:      cfg.Monitor.Thresholds.Memory,
		Disk:        cfg.Monitor.Thresholds.Disk,
		Consecutive: cfg.Monitor.Consecutive,
	})

	notifiers := make([]notify.Notifier, 0, 5)
	if cfg.Notify.Telegram.Enabled {
		notifiers = append(notifiers, notify.NewTelegramNotifier(cfg.Notify.Telegram.Token, cfg.Notify.Telegram.ChatID))
	}
	if cfg.Notify.WeChat.Enabled {
		notifiers = append(notifiers, notify.NewWeChatNotifier(cfg.Notify.WeChat.Webhook))
	}
	if cfg.Notify.IYUU.Enabled {
		notifiers = append(notifiers, notify.NewIYUUNotifier(cfg.Notify.IYUU.Token))
	}
	if cfg.Notify.Webhook.Enabled {
		notifiers = append(notifiers, notify.NewWebhookNotifier(cfg.Notify.Webhook.URL))
	}
	if cfg.Notify.PushPlus.Enabled {
		push := notify.NewPushPlusNotifier(cfg.Notify.PushPlus.Token).
			WithTemplate(cfg.Notify.PushPlus.Template).
			WithTopic(cfg.Notify.PushPlus.Topic)
		notifiers = append(notifiers, push)
	}

	var multi *notify.MultiNotifier
	if len(notifiers) > 0 {
		multi = notify.NewMultiNotifier(notifiers...)
	} else {
		log.Printf("warning: no notification channel enabled")
	}

	runner := service.NewRunner(collector, evaluator, multi, cfg.Monitor.Interval, log.Default())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var webServer *web.Server
	if cfg.Web.Enabled {
		webServer = web.NewServer(
			cfg.Web.Listen,
			*configPath,
			cfg.Web.AuthToken,
			cfg.Web.AllowedCIDRs,
			cfg.Web.RateLimitPerMinute,
			log.Default(),
		)
		go func() {
			if err := webServer.Start(); err != nil {
				log.Printf("web console stopped with error: %v", err)
				stop()
			}
		}()
		log.Printf("web console started: listen=%s", cfg.Web.Listen)
	}

	log.Printf("resource sentinel started: interval=%s", cfg.Monitor.Interval)
	runErr := runner.Run(ctx)

	if webServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := webServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("web console shutdown failed: %v", err)
		}
	}

	if runErr != nil {
		log.Fatalf("runner exited with error: %v", runErr)
	}
	log.Printf("resource sentinel stopped")
}
