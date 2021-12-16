package metrics

import "time"

type TimerMetric interface {
	Metric
	Start()
	Stop()
}

type timerMetric struct {
	name    string
	started time.Time
	total   time.Duration
}

// Timer returns a new timer (or returns an existing one if one exists with this category and name)
// The timer will be started on creation
func Timer(category string, name string, debug bool) TimerMetric {
	if metric := useCategory(category, debug).findMetric(name); metric != nil {
		if c, ok := metric.(TimerMetric); ok {
			c.Start()
			return c
		}
	}
	timer := &timerMetric{
		name:    name,
		started: time.Now(),
	}
	useCategory(category, debug).setMetric(timer)
	return timer
}

func (t *timerMetric) Start() {
	t.started = time.Now()
}

func (t *timerMetric) Stop() {
	t.total += time.Since(t.started)
}

func (t *timerMetric) Name() string {
	return t.name
}

func (t *timerMetric) Value() string {
	return t.total.String()
}
