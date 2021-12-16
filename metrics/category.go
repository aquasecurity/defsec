package metrics

import "fmt"

type category struct {
	name    string
	metrics []Metric
	debug   bool
}

func (c *category) Name() string {
	if c.debug {
		return fmt.Sprintf("debug: %s", c.name)
	}
	return c.name
}

func (c *category) Metrics() []Metric {
	return c.metrics
}

type Category interface {
	Name() string
	Metrics() []Metric
}

var registeredCategories []*category

// ClearSession removes all categories and metrics
func ClearSession() {
	registeredCategories = nil
}

// General returns general metrics that were recording during this session
func General() []Category {
	results := make([]Category, len(registeredCategories))
	for _, cat := range registeredCategories {
		if !cat.debug {
			results = append(results, cat)
		}
	}
	return results
}

// Debug returns debug metrics that were recording during this session
func Debug() []Category {
	results := make([]Category, len(registeredCategories))
	for _, cat := range registeredCategories {
		if cat.debug {
			results = append(results, cat)
		}
	}
	return results
}

func useCategory(name string, debug bool) *category {
	for _, registered := range registeredCategories {
		if registered.name == name {
			return registered
		}
	}
	cat := &category{
		name:    name,
		metrics: nil,
		debug:   debug,
	}
	registeredCategories = append(registeredCategories, cat)
	return cat
}

func (c *category) setMetric(m Metric) {
	for i, existing := range c.metrics {
		if existing == m {
			c.metrics[i] = m
			return
		}
	}
	c.metrics = append(c.metrics, m)
}

func (c *category) findMetric(name string) Metric {
	for _, existing := range c.metrics {
		if existing.Name() == name {
			return existing
		}
	}
	return nil
}
