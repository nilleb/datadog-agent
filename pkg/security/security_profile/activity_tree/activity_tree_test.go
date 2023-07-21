// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package activity_tree

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

func TestInsertFileEvent(t *testing.T) {
	pan := ProcessNode{
		Files: make(map[string]*FileNode),
	}
	pan.Process.FileEvent.PathnameStr = "/test/pan"
	stats := NewActivityTreeNodeStats()

	pathToInserts := []string{
		"/tmp/foo",
		"/tmp/bar",
		"/test/a/b/c/d/e/",
		"/hello",
		"/tmp/bar/test",
	}
	expectedDebugOuput := strings.TrimSpace(`
- process: /test/pan (is_exec_child:false)
  files:
    - hello
    - test
        - a
            - b
                - c
                    - d
                        - e
    - tmp
        - bar
            - test
        - foo
`)

	for _, path := range pathToInserts {
		event := &model.Event{
			BaseEvent: model.BaseEvent{
				FieldHandlers: &model.DefaultFieldHandlers{},
			},
			Open: model.OpenEvent{
				File: model.FileEvent{
					IsPathnameStrResolved: true,
					PathnameStr:           path,
				},
			},
		}
		pan.InsertFileEvent(&event.Open.File, event, Unknown, stats, false, nil, nil)
	}

	var builder strings.Builder
	pan.debug(&builder, "")
	debugOutput := strings.TrimSpace(builder.String())

	assert.Equal(t, expectedDebugOuput, debugOutput)
}

func TestActivityTree_InsertExecEvent(t *testing.T) {
	for _, tt := range ActivityTreeInsertExecEventTestCases {
		t.Run(tt.Name, func(t *testing.T) {
			node, _, newEntry, err := tt.Tree.CreateProcessNode(tt.InputEvent.ProcessCacheEntry, nil, Runtime, false, nil)
			if tt.wantErr != nil {
				if !tt.wantErr(t, err, fmt.Sprintf("unexpected error: %v", err)) {
					return
				}
			} else if err != nil {
				t.Fatalf("an err was returned but none was expected: %v", err)
				return
			}

			var builder strings.Builder
			tt.Tree.Debug(&builder)
			inputResult := strings.TrimSpace(builder.String())

			builder.Reset()
			tt.WantTree.Debug(&builder)
			wantedResult := strings.TrimSpace(builder.String())

			assert.Equalf(t, wantedResult, inputResult, "the generated tree didn't match the expected output")
			assert.Equalf(t, tt.wantNewEntry, newEntry, "invalid newEntry output")
			assert.Equalf(t, tt.wantNode.Process.FileEvent.PathnameStr, node.Process.FileEvent.PathnameStr, "the returned ProcessNode is invalid")

		})
	}
}
