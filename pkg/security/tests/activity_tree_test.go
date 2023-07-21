// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build functionaltests

package tests

import (
	"crypto/md5"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	adproto "github.com/DataDog/agent-payload/v5/cws/dumpsv1"
	"github.com/DataDog/datadog-agent/pkg/security/resolvers"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/activity_tree"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/dump"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/serializers"
)

var sharedTestSuiteDir = "pkg/security/tests/shared/"

func dumpTree(tree *activity_tree.ActivityTree, file string) error {
	pad := adproto.SecDump{
		Tree: activity_tree.ActivityTreeToProto(tree),
	}
	opts := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
		Indent:          "",
	}
	raw, err := opts.Marshal(&pad)
	if err != nil {
		return err
	}

	return os.WriteFile(file, raw, 0644)
}

var res *resolvers.Resolvers
var once sync.Once

func getResolvers(t *testing.T) *resolvers.Resolvers {
	rule := &rules.RuleDefinition{
		ID:         "test_rule",
		Expression: `open.file.path == "{{.Root}}/test-open" && open.flags & O_CREAT != 0`,
	}

	test, err := newTestModule(t, nil, []*rules.RuleDefinition{rule}, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return test.probe.GetResolvers()
}

func dumpEvent(t *testing.T, event *model.Event, file string) error {
	once.Do(func() {
		res = getResolvers(t)
	})

	raw, err := serializers.MarshalEvent(event, res)
	if err != nil {
		return err
	}

	return os.WriteFile(file, raw, 0644)
}

func TestExportActivityTreeTests(t *testing.T) {
	for _, tt := range activity_tree.ActivityTreeInsertExecEventTestCases {
		t.Run(tt.Name, func(t *testing.T) {
			name := strings.ReplaceAll(tt.Name, "/", "-")

			err := dumpTree(tt.Tree, sharedTestSuiteDir+name+"_input_tree.json")
			if err != nil {
				t.Error(err)
			}
			err = dumpTree(tt.WantTree, sharedTestSuiteDir+name+"_wanted_tree.json")
			if err != nil {
				t.Error(err)
			}
			err = dumpEvent(t, tt.InputEvent, sharedTestSuiteDir+name+"_input_event.json")
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func listTests(dir string) ([]string, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return []string{}, err
	}
	tests := []string{}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if strings.Contains(file.Name(), "_input_tree.json") {
			tests = append(tests, strings.ReplaceAll(file.Name(), "_input_tree.json", ""))
		}
	}
	return tests, nil
}

func isFilesEqual(file1, file2 string) (bool, error) {
	raw1, err := os.ReadFile(file1)
	if err != nil {
		return false, err
	}
	raw2, err := os.ReadFile(file2)
	if err != nil {
		return false, err
	}
	return md5.Sum(raw1) == md5.Sum(raw2), nil
}

func TestValidateExportedActivityTreeTests(t *testing.T) {
	tests, err := listTests(sharedTestSuiteDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			baseFile := path.Join(sharedTestSuiteDir, test+"_input_event.json")
			inputEvent, err := serializers.DecodeEvent(baseFile)
			if err != nil {
				t.Fatal(err)
			} else if inputEvent == nil {
				t.Fatal(errors.New("Empty event"))
			}

			// check to validate that the unmarshaled event is equal the one we previously marshaled
			clonedFile := path.Join(sharedTestSuiteDir, test+"_input_event.json"+".clone")
			err = dumpEvent(t, inputEvent, clonedFile)
			if err != nil {
				t.Error(err)
			}

			equal, err := isFilesEqual(baseFile, clonedFile)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equalf(t, true, equal, "files %f and %f differs", baseFile, clonedFile)

			os.Remove(clonedFile)
		})
	}
}

func TestActivityTreeTests(t *testing.T) {
	tests, err := listTests(sharedTestSuiteDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		adInputTree := dump.NewEmptyActivityDump(nil)
		adInputTree.Decode(path.Join(sharedTestSuiteDir, test+"_input_tree.json"))

		adWantedTree := dump.NewEmptyActivityDump(nil)
		adWantedTree.Decode(path.Join(sharedTestSuiteDir, test+"_wanted_tree.json"))

		inputEvent, err := serializers.DecodeEvent(path.Join(sharedTestSuiteDir, test+"_input_event.json"))
		if err != nil {
			t.Fatal(err)
		} else if inputEvent == nil {
			t.Fatal(errors.New("Empty event"))
		}

		t.Run(test, func(t *testing.T) {
			_, _, _, err := adInputTree.ActivityTree.CreateProcessNode(inputEvent.ProcessCacheEntry, nil, activity_tree.Runtime, false, nil)
			if err != nil {
				t.Fatal(err)
			}

			var builder strings.Builder
			adInputTree.ActivityTree.Debug(&builder)
			result := strings.TrimSpace(builder.String())

			builder.Reset()
			adWantedTree.ActivityTree.Debug(&builder)
			wantedResult := strings.TrimSpace(builder.String())

			assert.Equalf(t, wantedResult, result, "the generated tree didn't match the expected output")
		})
	}

}
