package monitor

import "time"

type MetricType string

const (
	MetricCPU    MetricType = "cpu"
	MetricMemory MetricType = "memory"
	MetricDisk   MetricType = "disk"
)

type EventType string

const (
	EventAlert   EventType = "alert"
	EventRecover EventType = "recover"
)

type Thresholds struct {
	CPU         float64
	Memory      float64
	Disk        float64
	Consecutive int
}

type Sample struct {
	CPU    float64
	Memory float64
	Disk   float64
	At     time.Time
}

type Event struct {
	Metric    MetricType
	Type      EventType
	Usage     float64
	Threshold float64
	At        time.Time
}

type Evaluator struct {
	thresholds Thresholds
	state      map[MetricType]*metricState
}

type metricState struct {
	hits     int
	alerting bool
}

func NewEvaluator(thresholds Thresholds) *Evaluator {
	if thresholds.Consecutive <= 0 {
		thresholds.Consecutive = 1
	}

	return &Evaluator{
		thresholds: thresholds,
		state: map[MetricType]*metricState{
			MetricCPU:    {},
			MetricMemory: {},
			MetricDisk:   {},
		},
	}
}

func (e *Evaluator) Evaluate(sample Sample) []Event {
	events := make([]Event, 0, 3)

	events = append(events, e.evaluateMetric(MetricCPU, sample.CPU, e.thresholds.CPU, sample.At)...) //nolint:makezero
	events = append(events, e.evaluateMetric(MetricMemory, sample.Memory, e.thresholds.Memory, sample.At)...)
	events = append(events, e.evaluateMetric(MetricDisk, sample.Disk, e.thresholds.Disk, sample.At)...)

	return events
}

func (e *Evaluator) evaluateMetric(metric MetricType, usage, threshold float64, at time.Time) []Event {
	if threshold <= 0 {
		return nil
	}

	state := e.state[metric]
	if usage >= threshold {
		state.hits++
		if !state.alerting && state.hits >= e.thresholds.Consecutive {
			state.alerting = true
			return []Event{{
				Metric:    metric,
				Type:      EventAlert,
				Usage:     usage,
				Threshold: threshold,
				At:        at,
			}}
		}
		return nil
	}

	state.hits = 0
	if state.alerting {
		state.alerting = false
		return []Event{{
			Metric:    metric,
			Type:      EventRecover,
			Usage:     usage,
			Threshold: threshold,
			At:        at,
		}}
	}
	return nil
}
