// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//go:build !linux && !windows

package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/probe/kfilters"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

// EventHandler represents an handler for the events sent by the probe
type EventHandler interface{}

// PlatformProbe represents the no-op platform probe on unsupported platforms
type PlatformProbe struct {
}

// Probe represents the runtime security probe
type Probe struct {
	Config *config.Config
}

// AddEventHandler set the probe event handler
func (p *Probe) AddEventHandler(eventType model.EventType, handler EventHandler) error {
	return nil
}

// NewEvaluationSet returns a new evaluation set with rule sets tagged by the passed-in tag values for the "ruleset" tag key
func (p *Probe) NewEvaluationSet(eventTypeEnabled map[eval.EventType]bool, ruleSetTagValues []string) (*rules.EvaluationSet, error) {
	return nil, nil
}

// ApplyRuleSet setup the probes for the provided set of rules and returns the policy report.
func (p *Probe) ApplyRuleSet(rs *rules.RuleSet) (*kfilters.ApplyRuleSetReport, error) {
	return nil, nil
}

// OnNewDiscarder is called when a new discarder is found. We currently don't generate discarders on Windows.
func (p *Probe) OnNewDiscarder(rs *rules.RuleSet, ev *model.Event, field eval.Field, eventType eval.EventType) {
}

// GetService returns the service name from the process tree
func (p *Probe) GetService(ev *model.Event) string {
	return ""
}

// GetEventTags returns the event tags
func (p *Probe) GetEventTags(containerID string) []string {
	return nil
}

// IsNetworkEnabled returns whether network is enabled
func (p *Probe) IsNetworkEnabled() bool {
	return p.Config.Probe.NetworkEnabled
}
