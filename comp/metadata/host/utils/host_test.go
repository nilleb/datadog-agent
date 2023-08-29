// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package utils

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestOTLPEnabled(t *testing.T) {
	ctx := context.Background()
	conf := config.Mock(t)

	defer func(orig func(cfg config.ConfigReader) bool) { otlpIsEnabled = orig }(otlpIsEnabled)

	otlpIsEnabled = func(config.ConfigReader) bool { return false }
	p := GetPayload(ctx, conf)
	assert.False(t, p.OtlpMeta.Enabled)

	otlpIsEnabled = func(config.ConfigReader) bool { return true }
	p = GetPayload(ctx, conf)
	assert.True(t, p.OtlpMeta.Enabled)
}
