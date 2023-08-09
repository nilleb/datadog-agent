// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package utils

import (
	"runtime"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/collector/python"
	"github.com/DataDog/datadog-agent/pkg/gohai/cpu"
	"github.com/DataDog/datadog-agent/pkg/util/cache"
)

// Set the OS to "win32" instead of the runtime.GOOS of "windows" for the in app icon
const osName = "win32"

// osVersion this is a legacy representation of OS version dating back to agent V5 which was in Python. In V5 the
// content of this list changed based on the OS.
type osVersion [2]string

func getSystemStats() *systemStats {
	cache.Get[*systemStats](
		systemStatsCacheKey,
		func() (*systemStatsCacheKey, error) {

			cpuInfo := cpu.CollectInfo()
			cores := cpuInfo.CPUCores.ValueOrDefault()
			c32 := int32(cores)
			modelName := cpuInfo.ModelName.ValueOrDefault()

			stats := &systemStats{
				Machine:   runtime.GOARCH,
				Platform:  runtime.GOOS,
				Processor: modelName,
				CPUCores:  c32,
				Pythonv:   python.GetPythonVersion(),
			}

			hostInfo := hostMetadataUtils.GetInformation()

			// osVersion is a legacy representation of OS version dating back to agent V5 which was in
			// Python2. In V5 the content of this list changed based on the OS:
			//
			// - Macver was the result of `platform.mac_ver()`
			// - Nixver was the result of `platform.dist()`
			// - Winver was the result of `platform.win32_ver()`
			stats.Winver = osVersion{hostInfo.Platform, hostInfo.PlatformVersion}

			hostVersion := strings.Trim(hostInfo.Platform+" "+hostInfo.PlatformVersion, " ")
			inventories.SetHostMetadata(inventories.HostOSVersion, hostVersion)
			return stats, nil
		},
	)
}
