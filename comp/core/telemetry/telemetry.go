// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TODO (components): Remove the global and move this into `newTelemetry` after all telemetry is migrated to the component
var (
	registry = func() *prometheus.Registry {
		registry := prometheus.NewRegistry()
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		registry.MustRegister(collectors.NewGoCollector())
		return registry
	}()
)

type telemetryImpl struct {
	registry *prometheus.Registry
}

func newTelemetry() Component {
	return &telemetryImpl{
		registry: registry,
	}
}

// TODO (components): Remove this when all telemetry is migrated to the component
func GetCompatComponent() Component {
	return newTelemetry()
}

func (t *telemetryImpl) Handler() http.Handler {
	return promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{})
}

func (t *telemetryImpl) Reset() {
	registry = prometheus.NewRegistry()
	t.registry = registry
}

func (t *telemetryImpl) NewCounter(subsystem, name string, tags []string, help string) Counter {
	return t.NewCounterWithOpts(subsystem, name, tags, help, DefaultOptions)
}

func (t *telemetryImpl) NewCounterWithOpts(subsystem, name string, tags []string, help string, opts Options) Counter {
	name = opts.NameWithSeparator(subsystem, name)

	c := &promCounter{
		pc: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Subsystem: subsystem,
				Name:      name,
				Help:      help,
			},
			tags,
		),
	}
	t.registry.Register(c.pc)
	return c
}

func (t *telemetryImpl) NewGauge(subsystem, name string, tags []string, help string) Gauge {
	return t.NewGaugeWithOpts(subsystem, name, tags, help, DefaultOptions)
}

func (t *telemetryImpl) NewGaugeWithOpts(subsystem, name string, tags []string, help string, opts Options) Gauge {
	name = opts.NameWithSeparator(subsystem, name)

	g := &promGauge{
		pg: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Subsystem: subsystem,
				Name:      name,
				Help:      help,
			},
			tags,
		),
	}
	t.registry.Register(g.pg)
	return g
}
