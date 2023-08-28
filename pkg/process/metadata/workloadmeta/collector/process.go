// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package collector

import (
	"context"
	"github.com/DataDog/datadog-agent/pkg/languagedetection"
	"github.com/DataDog/datadog-agent/pkg/languagedetection/languagemodels"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"strconv"
	"time"

	"github.com/benbjohnson/clock"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	workloadmetaExtractor "github.com/DataDog/datadog-agent/pkg/process/metadata/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

const collectorId = "local-process"

// NewProcessCollector creates a new process collector.
func NewProcessCollector(coreConfig, sysProbeConfig config.ConfigReader) *Collector {
	return &Collector{
		sysprobeConfig:  sysProbeConfig,
		ddConfig:        coreConfig,
		collectionClock: clock.New(),
		pidToCid:        make(map[int]string),
		probe:           procutil.NewProcessProbe(),
	}
}

// Collector collects processes to send to the remote process collector in the core agent.
// It is only intended to be used when language detection is enabled, and the process check is disabled.
type Collector struct {
	ddConfig       config.ConfigReader
	sysprobeConfig config.ConfigReader

	processData *checks.ProcessData

	wlmExtractor *workloadmetaExtractor.WorkloadMetaExtractor
	grpcServer   *workloadmetaExtractor.GRPCServer

	pidToCid  map[int]string
	procCache map[string]*workloadmeta.Process

	probe procutil.Probe

	collectionClock clock.Clock
}

func (c *Collector) Start(ctx context.Context, store workloadmeta.Store) error {
	err := c.grpcServer.Start()
	if err != nil {
		return err
	}

	collectionTicker := c.collectionClock.Ticker(
		c.ddConfig.GetDuration("workloadmeta.local_process_collector.collection_interval"),
	)

	filter := workloadmeta.NewFilter([]workloadmeta.Kind{workloadmeta.KindContainer}, workloadmeta.SourceAll, workloadmeta.EventTypeAll)
	containerEvt := store.Subscribe(collectorId, workloadmeta.NormalPriority, filter)

	go c.run(ctx, store, containerEvt, collectionTicker)

	return nil
}

func (c *Collector) run(ctx context.Context, store workloadmeta.Store, containerEvt chan workloadmeta.EventBundle, collectionTicker *clock.Ticker) {
	defer c.grpcServer.Stop()
	defer store.Unsubscribe(containerEvt)
	defer collectionTicker.Stop()

	log.Info("Starting local process collection server")

	for {
		select {
		case evt := <-containerEvt:
			c.handleContainerEvent(evt)
		case <-collectionTicker.C:
			err := c.processData.Fetch()
			if err != nil {
				log.Error("Error fetching process data:", err)
			}
		case <-ctx.Done():
			log.Infof("The %s collector has stopped", collectorId)
			return
		}
	}
}

func (c *Collector) collectProcesses(store workloadmeta.Store) {
	procs, _ := c.probe.ProcessesByPID(time.Now(), false)
	newEntities := make([]*workloadmeta.Process, 0, len(procs))
	newProcs := make([]languagemodels.Process, 0, len(procs))
	newCache := make(map[string]*workloadmeta.Process, len(procs))
	for pid, proc := range procs {
		hash := hashProcess(pid, proc.Stats.CreateTime)
		if entity, ok := c.procCache[hash]; ok {
			newCache[hash] = entity

			// Sometimes the containerID can be late to initialize. If this is the case add it to the list of changed procs
			if cid, ok := c.pidToCid[int(proc.Pid)]; ok && entity.ContainerId == "" {
				entity.ContainerId = cid
				newEntities = append(newEntities, entity)
			}
			continue
		}

		newProcs = append(newProcs, proc)
	}

	deadProcs := getDifference(c.procCache, newCache)

	// If no process has been created, terminated, or updated, there's no need to update the cache
	// or generate a new diff
	if len(newProcs) == 0 && len(deadProcs) == 0 && len(newEntities) == 0 {
		return
	}

	languages := languagedetection.DetectLanguage(newProcs, c.ddConfig)
	for i, lang := range languages {
		pid := newProcs[i].GetPid()
		proc := procs[pid]

		var creationTime int64
		if proc.Stats != nil {
			creationTime = proc.Stats.CreateTime
		}

		entity := &workloadmeta.Process{
			EntityID: workloadmeta.EntityID{
				Kind: workloadmeta.KindProcess,
				ID:   strconv.Itoa(int(pid)),
			},
			NsPid:        proc.NsPid,
			CreationTime: time.UnixMilli(creationTime),
			Language:     lang,
			ContainerId:  c.pidToCid[int(pid)],
		}
		newEntities = append(newEntities, entity)
		newCache[hashProcess(pid, proc.Stats.CreateTime)] = entity

		log.Trace("detected language", lang.Name, "for pid", pid)
	}

	c.procCache = newCache

	evts := make([]workloadmeta.CollectorEvent, 0, len(newProcs)+len(deadProcs))
	for _, proc := range newEntities {
		evts = append(evts, workloadmeta.CollectorEvent{
			Type:   workloadmeta.EventTypeSet,
			Source: workloadmeta.SourceRuntime,
			Entity: proc,
		})
	}
	for _, proc := range deadProcs {
		evts = append(evts, workloadmeta.CollectorEvent{
			Type:   workloadmeta.EventTypeUnset,
			Source: workloadmeta.SourceRuntime,
			Entity: proc,
		})
	}
}

// Pull is unused at the moment used due to the short frequency in which it is called.
// In the future, we should use it to poll for processes that have been collected and store them in workload-meta.

func (c *Collector) handleContainerEvent(evt workloadmeta.EventBundle) {
	defer close(evt.Ch)

	for _, evt := range evt.Events {
		ent := evt.Entity.(*workloadmeta.Container)
		switch evt.Type {
		case workloadmeta.EventTypeSet:
			// Should be safe, even on windows because PID 0 is the idle process and therefore must always belong to the host
			if ent.PID != 0 {
				c.pidToCid[ent.PID] = ent.ID
			}
		case workloadmeta.EventTypeUnset:
			delete(c.pidToCid, ent.PID)
		}
	}

	c.wlmExtractor.SetLastPidToCid(c.pidToCid)
}

// Enabled checks to see if we should enable the local process collector.
// Since it's job is to collect processes when the process check is disabled, we only enable it when `process_config.process_collection.enabled` == false
// Additionally, if the remote process collector is not enabled in the core agent, there is no reason to collect processes. Therefore, we check `language_detection.enabled`
// Finally, we only want to run this collector in the process agent, so if we're running as anything else we should disable the collector.
func Enabled(cfg config.ConfigReader) bool {
	if cfg.GetBool("process_config.process_collection.enabled") {
		return false
	}

	if !cfg.GetBool("language_detection.enabled") {
		return false
	}
	return true
}

func hashProcess(pid int32, createTime int64) string {
	return "pid:" + strconv.Itoa(int(pid)) + "|createTime:" + strconv.Itoa(int(createTime))
}

func getDifference(oldCache, newCache map[string]*workloadmeta.Process) []*workloadmeta.Process {
	oldProcs := make([]*workloadmeta.Process, 0, len(oldCache))
	for key, entity := range oldCache {
		if _, ok := newCache[key]; ok {
			continue
		}
		oldProcs = append(oldProcs, entity)
	}
	return oldProcs
}
