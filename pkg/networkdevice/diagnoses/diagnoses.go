// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

// Package diagnoses implements the diagnosis collection for NDM resources
package diagnoses

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"
	"github.com/DataDog/datadog-agent/pkg/networkdevice/metadata"
)

// Diagnoses hold diagnoses for a NDM resource
type Diagnoses struct {
	resourceType  string
	resourceID    string
	diagnoses     []metadata.Diagnosis
	prevDiagnoses []metadata.Diagnosis
}

var severityMap = map[string]diagnosis.Result{
	"success": diagnosis.DiagnosisSuccess,
	"error":   diagnosis.DiagnosisFail,
	"warn":    diagnosis.DiagnosisWarning,
}

// NewDeviceDiagnoses returns a new Diagnoses for a NDM device resource
func NewDeviceDiagnoses(deviceID string) *Diagnoses {
	return &Diagnoses{
		resourceType: "device",
		resourceID:   deviceID,
	}
}

// Add adds a diagnoses
func (d *Diagnoses) Add(result string, code string, message string) {
	d.diagnoses = append(d.diagnoses, metadata.Diagnosis{
		Severity: result,
		Code:     code,
		Message:  message,
	})
}

// Report returns diagnosis metadata
func (d *Diagnoses) Report() []metadata.DiagnosisMetadata {
	if len(d.prevDiagnoses) > 0 && len(d.diagnoses) == 0 {
		d.resetDiagnoses()
		// Sending an empty array of diagnoses
		return []metadata.DiagnosisMetadata{{ResourceType: d.resourceType, ResourceID: d.resourceID, Diagnoses: []metadata.Diagnosis{}}}
	}

	d.resetDiagnoses()

	if d.prevDiagnoses == nil {
		return nil
	}

	return []metadata.DiagnosisMetadata{{ResourceType: d.resourceType, ResourceID: d.resourceID, Diagnoses: d.prevDiagnoses}}
}

// resetDiagnoses clears current diagnoses
func (d *Diagnoses) resetDiagnoses() {
	d.prevDiagnoses = d.diagnoses
	d.diagnoses = nil
}

// ConvertToCLI converts diagnoses to diagnose CLI format
func (d *Diagnoses) ConvertToCLI() []diagnosis.Diagnosis {
	var cliDiagnoses []diagnosis.Diagnosis

	for _, diag := range d.prevDiagnoses {
		cliDiagnoses = append(cliDiagnoses, diagnosis.Diagnosis{
			Result:    severityMap[diag.Severity],
			Name:      fmt.Sprintf("NDM %s - %s - %s", d.resourceType, d.resourceID, diag.Code),
			Diagnosis: diag.Message,
		})
	}

	return cliDiagnoses
}
