// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package modules

import (
	"fmt"
	"io"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/languagedetection"
	"github.com/DataDog/datadog-agent/pkg/languagedetection/languagemodels"
	languageDetectionProto "github.com/DataDog/datadog-agent/pkg/proto/pbgo/languagedetection"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var LanguageDetectionModule = module.Factory{
	Name:             config.LanguageDetectionModule,
	ConfigNamespaces: []string{"language_detection"},
	Fn: func(cfg *config.Config) (module.Module, error) {
		return languageDetectionModule{}, nil
	},
}

type languageDetectionModule struct{}

func (l languageDetectionModule) GetStats() map[string]interface{} {
	return nil
}

func (l languageDetectionModule) Register(router *module.Router) error {
	router.HandleFunc("/detect", detectLanguage)
	return nil
}

// Close closes resources associated with the language detection module.
// The language detection module doesn't do anything except route to the privileged language detection api.
// This API currently does not hold any resources over its lifetime, so there is no need to release any resources when the
// module is closed.

func (l languageDetectionModule) Close() {}

func getRequestPids(proto *languageDetectionProto.DetectLanguageRequest) []int {
	pids := make([]int, len(proto.Processes))
	for i, lang := range proto.GetProcesses() {
		pids[i] = int(lang.Pid)
	}
	return pids
}

func toDetectLanguageResponse(langs []languagemodels.Language) *languageDetectionProto.DetectLanguageResponse {
	resp := &languageDetectionProto.DetectLanguageResponse{
		Languages: make([]*languageDetectionProto.Language, len(langs)),
	}
	for i, lang := range langs {
		resp.Languages[i] = &languageDetectionProto.Language{
			Name:    string(lang.Name),
			Version: lang.Version,
		}
	}
	return resp
}

func handleError(writer http.ResponseWriter, status int, err error) {
	_ = log.Error("Failed to properly handle /language_detection/detect request:", err)
	writer.WriteHeader(status)
}

func detectLanguage(writer http.ResponseWriter, request *http.Request) {
	b, err := io.ReadAll(request.Body)
	if err != nil {
		handleError(writer, http.StatusInternalServerError, fmt.Errorf("read request body: %v", err))
		return
	}
	defer request.Body.Close()

	var req languageDetectionProto.DetectLanguageRequest
	if err := proto.Unmarshal(b, &req); err != nil {
		handleError(writer, http.StatusInternalServerError, fmt.Errorf("unmarshal request: %v", err))
		return
	}

	resp := toDetectLanguageResponse(languagedetection.DetectWithPrivileges(getRequestPids(&req)))
	b, err = proto.Marshal(resp)
	if err != nil {
		handleError(writer, http.StatusInternalServerError, fmt.Errorf("seralize response: %v", err))
		return
	}

	_, err = writer.Write(b)
	if err != nil {
		log.Error("/language_detection/detect succeeded but failed to write a response:", err.Error())
	}
}
