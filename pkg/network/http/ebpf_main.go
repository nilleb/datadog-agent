// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"fmt"
	"math"
	"os"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	httpInFlightMap          = "http_in_flight"
	httpBatchesMap           = "http_batches"
	httpBatchStateMap        = "http_batch_state"
	httpNotificationsPerfMap = "http_notifications"

	// ELF section of the BPF_PROG_TYPE_SOCKET_FILTER program used
	// to inspect plain HTTP traffic
	httpSocketFilterStub = "socket/http_filter_entry"
	httpSocketFilter     = "socket/http_filter"
	HTTP_PROG            = 0
	httpProgsMap         = "http_progs"

	// maxActive configures the maximum number of instances of the
	// kretprobe-probed functions handled simultaneously.  This value should be
	// enough for typical workloads (e.g. some amount of processes blocked on
	// the accept syscall).
	maxActive = 128

	// size of the channel containing completed http_notification_objects
	batchNotificationsChanSize = 100

	probeUID = "http"

	maxRequestLinger = 30 * time.Second
)

type ebpfProgram struct {
	*manager.Manager
	cfg         *config.Config
	bytecode    bytecode.AssetReader
	offsets     []manager.ConstantEditor
	subprograms []subprogram
	mapCleaner  *ddebpf.MapCleaner

	batchCompletionHandler *netebpf.PerfMap
}

type subprogram interface {
	Configure(*manager.Manager, *manager.Options) error
	Start() error
	Stop()
}

func newEBPFProgram(c *config.Config, offsets []manager.ConstantEditor, sockFD *ebpf.Map) (*ebpfProgram, error) {
	var bc bytecode.AssetReader
	var err error
	if enableRuntimeCompilation(c) {
		bc, err = getRuntimeCompiledHTTP(c)
		if err != nil {
			if !c.AllowPrecompiledFallback {
				return nil, fmt.Errorf("error compiling network http tracer: %s", err)
			}
			log.Warnf("error compiling network http tracer, falling back to pre-compiled: %s", err)
		}
	}

	if bc == nil {
		bc, err = netebpf.ReadHTTPModule(c.BPFDir, c.BPFDebug)
		if err != nil {
			return nil, fmt.Errorf("could not read bpf module: %s", err)
		}
	}

	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: httpInFlightMap},
			{Name: httpBatchesMap},
			{Name: httpBatchStateMap},
			{Name: sslSockByCtxMap},
			{Name: httpProgsMap},
			{Name: "ssl_read_args"},
			{Name: "bio_new_socket_args"},
			{Name: "fd_by_ssl_bio"},
			{Name: "ssl_ctx_by_pid_tgid"},
		},
		Probes: []*manager.Probe{
			{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFSection: string(probes.TCPSendMsg), EBPFFuncName: "kprobe__tcp_sendmsg", UID: probeUID}, KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFSection: string(probes.TCPSendMsgReturn), EBPFFuncName: "kretprobe__tcp_sendmsg", UID: probeUID}, KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFSection: httpSocketFilterStub, EBPFFuncName: "socket__http_filter_entry", UID: probeUID}},
		},
	}

	sslProgram, _ := newSSLProgram(c, sockFD)
	program := &ebpfProgram{
		Manager:     mgr,
		bytecode:    bc,
		cfg:         c,
		offsets:     offsets,
		subprograms: []subprogram{sslProgram},
	}

	return program, nil
}

func (e *ebpfProgram) Init() error {
	defer e.bytecode.Close()

	options := manager.Options{
		DefaultWatermark:          1,
		DefaultPerfRingBufferSize: 8 * os.Getpagesize(),
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			httpInFlightMap: {
				Type:       ebpf.Hash,
				MaxEntries: uint32(e.cfg.MaxTrackedConnections),
				EditorFlag: manager.EditMaxEntries,
			},
		},
		TailCallRouter: []manager.TailCallRoute{
			{
				ProgArrayName: httpProgsMap,
				Key:           HTTP_PROG,
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  httpSocketFilter,
					EBPFFuncName: "socket__http_filter",
				},
			},
		},
		ActivatedProbes: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  httpSocketFilterStub,
					EBPFFuncName: "socket__http_filter_entry",
					UID:          probeUID,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  string(probes.TCPSendMsg),
					EBPFFuncName: "kprobe__tcp_sendmsg",
					UID:          probeUID,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  string(probes.TCPSendMsgReturn),
					EBPFFuncName: "kretprobe__tcp_sendmsg",
					UID:          probeUID,
				},
			},
		},
		ConstantEditors: e.offsets,
	}

	for _, s := range e.subprograms {
		if err := s.Configure(e.Manager, &options); err != nil {
			return fmt.Errorf("error configuring manager for subprogram: %w", err)
		}
	}
	e.Manager.DumpHandler = dumpMapsHandler

	var err error
	e.batchCompletionHandler, err = netebpf.NewPerfMap(httpNotificationsPerfMap, e.Manager, &options)
	if err != nil {
		return err
	}

	return e.InitWithOptions(e.bytecode, options)
}

func (e *ebpfProgram) Start() error {
	err := e.Manager.Start()
	if err != nil {
		return err
	}

	for _, s := range e.subprograms {
		s.Start()
	}

	e.setupMapCleaner()

	return nil
}

func (e *ebpfProgram) Close() error {
	e.mapCleaner.Stop()
	err := e.Manager.Stop(manager.CleanAll)
	e.batchCompletionHandler.Stop()
	for _, s := range e.subprograms {
		s.Stop()
	}
	return err
}

func (e *ebpfProgram) setupMapCleaner() {
	httpMap, _, _ := e.GetMap(httpInFlightMap)
	httpMapCleaner, err := ddebpf.NewMapCleaner(httpMap, new(netebpf.ConnTuple), new(httpTX))
	if err != nil {
		log.Errorf("error creating map cleaner: %s", err)
		return
	}

	ttl := maxRequestLinger.Nanoseconds()
	httpMapCleaner.Clean(5*time.Minute, func(now int64, key, val interface{}) bool {
		httpTX, ok := val.(*httpTX)
		if !ok {
			return false
		}

		if updated := int64(httpTX.response_last_seen); updated > 0 {
			return (now - updated) > ttl
		}

		started := int64(httpTX.request_started)
		return started > 0 && (now-started) > ttl
	})

	e.mapCleaner = httpMapCleaner
}

func enableRuntimeCompilation(c *config.Config) bool {
	if !c.EnableRuntimeCompiler {
		return false
	}

	// The runtime-compiled version of HTTP monitoring requires Kernel 4.5
	// because we use the `bpf_skb_load_bytes` helper.
	kversion, err := kernel.HostVersion()
	if err != nil {
		log.Warn("could not determine the current kernel version. falling back to pre-compiled program.")
		return false
	}

	return kversion >= kernel.VersionCode(4, 5, 0)
}
