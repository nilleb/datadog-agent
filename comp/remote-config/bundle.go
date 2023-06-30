// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package remoteconfig

import (
	"github.com/DataDog/datadog-agent/comp/remote-config/rcclient"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// team: remote-config

// Bundle defines the fx options for this bundle.
var Bundle = fxutil.Bundle(
	rcclient.Module,
)
