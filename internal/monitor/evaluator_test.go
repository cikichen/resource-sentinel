package monitor

import (
	"testing"
	"time"
)

func TestEvaluatorAlertAndRecover(t *testing.T) {
	e := NewEvaluator(Thresholds{
		CPU:         80,
		Memory:      75,
		Disk:        90,
		Consecutive: 2,
	})

	now := time.Now()
	if events := e.Evaluate(Sample{CPU: 81, Memory: 60, Disk: 50, At: now}); len(events) != 0 {
		t.Fatalf("expected no events on first breach, got %d", len(events))
	}

	events := e.Evaluate(Sample{CPU: 85, Memory: 60, Disk: 50, At: now.Add(time.Second)})
	if len(events) != 1 {
		t.Fatalf("expected 1 alert event, got %d", len(events))
	}
	if events[0].Metric != MetricCPU || events[0].Type != EventAlert {
		t.Fatalf("unexpected event: %+v", events[0])
	}

	if events := e.Evaluate(Sample{CPU: 86, Memory: 60, Disk: 50, At: now.Add(2 * time.Second)}); len(events) != 0 {
		t.Fatalf("expected no duplicated alert when already alerting, got %d", len(events))
	}

	events = e.Evaluate(Sample{CPU: 30, Memory: 60, Disk: 50, At: now.Add(3 * time.Second)})
	if len(events) != 1 {
		t.Fatalf("expected 1 recover event, got %d", len(events))
	}
	if events[0].Metric != MetricCPU || events[0].Type != EventRecover {
		t.Fatalf("unexpected recover event: %+v", events[0])
	}
}

func TestEvaluatorMultiMetricIndependence(t *testing.T) {
	e := NewEvaluator(Thresholds{
		CPU:         90,
		Memory:      70,
		Disk:        80,
		Consecutive: 1,
	})

	events := e.Evaluate(Sample{CPU: 20, Memory: 75, Disk: 85, At: time.Now()})
	if len(events) != 2 {
		t.Fatalf("expected memory and disk alert, got %d", len(events))
	}

	seen := map[MetricType]EventType{}
	for _, event := range events {
		seen[event.Metric] = event.Type
	}

	if seen[MetricMemory] != EventAlert {
		t.Fatalf("expected memory alert, got %v", seen[MetricMemory])
	}
	if seen[MetricDisk] != EventAlert {
		t.Fatalf("expected disk alert, got %v", seen[MetricDisk])
	}
	if _, ok := seen[MetricCPU]; ok {
		t.Fatal("cpu should not alert")
	}
}
