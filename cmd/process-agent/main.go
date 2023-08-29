// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package main

import (
	"context"
	"os"

	"github.com/DataDog/datadog-agent/cmd/process-agent/command"
)

const useWinParams = false

func rootCmdRun(globalParams *command.GlobalParams) {
	// Invoke the Agent
	err := runAgent(context.Background(), globalParams)
	if err != nil {
		// For compatibility with the previous cleanupAndExitHandler implementation, os.Exit() on error.
		// This prevents runcmd.Run() from displaying the error.
		os.Exit(1)
	}
}
