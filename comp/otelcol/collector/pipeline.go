// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
package collector

import (
	"context"

	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/core/config"
	corelog "github.com/DataDog/datadog-agent/comp/core/log"
	logsagent "github.com/DataDog/datadog-agent/comp/logs/agent"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/metadata/inventories"
	"github.com/DataDog/datadog-agent/pkg/otlp"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/util"
)

// dependencies specifies a list of dependencies required for the collector
// to be instantiated.
type dependencies struct {
	fx.In

	// Lc specifies the fx lifecycle settings, used for appending startup
	// and shutdown hooks.
	Lc fx.Lifecycle

	// Config specifies the Datadog Agent's configuration component.
	Config config.Component

	// Log specifies the logging component.
	Log corelog.Component

	// Serializer specifies the metrics serializer that is used to export metrics
	// to Datadog.
	Serializer serializer.MetricSerializer

	// LogsAgent specifies a logs agent
	LogsAgent util.Optional[logsagent.Component]
}

// newPipeline creates a new Component for this module and returns any errors on failure.
func newPipeline(deps dependencies) (Component, error) {
	on := otlp.IsEnabled(deps.Config)
	inventories.SetAgentMetadata(inventories.AgentOTLPEnabled, on)
	if !on {
		return nil, nil
	}
	// we can only create the pipeline OnStart because the logs
	// agent isn't ready to provide a channel at this point
	var col *otlp.Pipeline
	deps.Lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			var logch chan *message.Message
			if v, ok := deps.LogsAgent.Get(); ok {
				logch = v.GetPipelineProvider().NextPipelineChan()
			}
			var err error
			col, err = otlp.NewPipelineFromAgentConfig(deps.Config, deps.Serializer, logch)
			if err != nil {
				// failure to start the OTLP component shouldn't fail startup
				deps.Log.Errorf("Error creating the OTLP pipeline: %v", err)
				return nil
			}
			// the context passed to this function has a startup deadline which
			// will shutdown the collector prematurely
			ctx := context.Background()
			go func() {
				if err := col.Run(ctx); err != nil {
					deps.Log.Errorf("Error starting the OTLP pipeline: %v", err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if col != nil {
				col.Stop()
			}
			return nil
		},
	})
	return col, nil
}
