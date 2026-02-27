package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
	applyGlobalProxy(cfg.Network.ProxyURL)

	collector := monitor.NewSystemCollector(cfg.Monitor.DiskPath, cfg.Monitor.CPUWindow)
	evaluator := monitor.NewEvaluator(monitor.Thresholds{
		CPU:         cfg.Monitor.Thresholds.CPU,
		Memory:      cfg.Monitor.Thresholds.Memory,
		Disk:        cfg.Monitor.Thresholds.Disk,
		Consecutive: cfg.Monitor.Consecutive,
	})

	notifiers := make([]notify.Notifier, 0, 5)
	if cfg.Notify.Telegram.Enabled {
		notifiers = append(notifiers, notify.NewTelegramNotifier(
			cfg.Notify.Telegram.Token,
			cfg.Notify.Telegram.ChatID,
			cfg.Notify.Telegram.APIBase,
			cfg.Network.ProxyURL,
		))
	}
	if cfg.Notify.WeChat.Enabled {
		notifiers = append(notifiers, notify.NewWeChatNotifier(cfg.Notify.WeChat.Webhook, cfg.Network.ProxyURL))
	}
	if cfg.Notify.IYUU.Enabled {
		notifiers = append(notifiers, notify.NewIYUUNotifier(cfg.Notify.IYUU.Token, cfg.Network.ProxyURL))
	}
	if cfg.Notify.Webhook.Enabled {
		notifiers = append(notifiers, notify.NewWebhookNotifier(cfg.Notify.Webhook.URL, cfg.Network.ProxyURL))
	}
	if cfg.Notify.PushPlus.Enabled {
		push := notify.NewPushPlusNotifier(cfg.Notify.PushPlus.Token, cfg.Network.ProxyURL).
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

func applyGlobalProxy(proxyURL string) {
	cleanProxy := strings.TrimSpace(proxyURL)
	if cleanProxy == "" {
		return
	}
	parsed, err := url.Parse(cleanProxy)
	if err != nil {
		log.Printf("warning: ignore invalid global proxy url %q: %v", cleanProxy, err)
		return
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		log.Printf("warning: unsupported default transport type %T, skip global proxy", http.DefaultTransport)
		return
	}

	cloned := transport.Clone()
	cloned.Proxy = http.ProxyURL(parsed)
	http.DefaultTransport = cloned
	log.Printf("global proxy enabled: %s", cleanProxy)
}
