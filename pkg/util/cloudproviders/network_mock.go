// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test

package cloudproviders

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/util/cache"
)

func MockNetworkID(t *testing.T, networkID string) {
	t.Cleanup(func() { cache.Cache.Delete(networkIDCacheKey) })
	cache.Cache.Set(networkIDCacheKey, networkID, cache.NoExpiration)
}
