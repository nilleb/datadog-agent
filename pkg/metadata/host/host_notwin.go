// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

package host

import (
	"github.com/shirou/gopsutil/v3/cpu"
)

// InitHostMetadata initializes necessary CPU info
func InitHostMetadata() error {
	var err error
	_, err = cpu.Info()
	return err
}
