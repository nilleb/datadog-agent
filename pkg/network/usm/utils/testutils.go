// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf && test

package utils

import "sync"

// IgnoreCB is just a dummy callback that doesn't do anything
// Meant for testing purposes
var IgnoreCB = func(FilePath) error { return nil }

// CallbackRecorder is meant to assist with *testing* the `FileRegistry` code
// as well as code interacting with it such as `sharedlibraries.Watcher`.
// A callback "mock" can be generated by calling `Callback()`, which essentially
// counts the number of callback executions and returns an injected error when needed.
type CallbackRecorder struct {
	mux           sync.Mutex
	ReturnError   error
	callsByPathID map[PathIdentifier]int
}

// Callback returns a *testing* callback that can be used as an argument to
// `FileRegistry.Register()`
// Note that this method should be called only once.
func (r *CallbackRecorder) Callback() func(FilePath) error {
	return func(f FilePath) error {
		r.mux.Lock()
		defer r.mux.Unlock()

		if r.callsByPathID == nil {
			r.callsByPathID = make(map[PathIdentifier]int)
		}

		r.callsByPathID[f.ID]++

		return r.ReturnError
	}
}

// `CallsForPathID` returns the number of callback executions for a given `PathIdentifier`
func (r *CallbackRecorder) CallsForPathID(pathID PathIdentifier) int {
	r.mux.Lock()
	defer r.mux.Unlock()

	return r.callsByPathID[pathID]
}

// TotalCalls returns the total number of calls the callback has received
func (r *CallbackRecorder) TotalCalls() int {
	r.mux.Lock()
	defer r.mux.Unlock()

	total := 0
	for _, count := range r.callsByPathID {
		total += count
	}
	return total
}
