// This file is licensed under the MIT License.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright © 2015 Kentaro Kuribayashi <kentarok@gmail.com>
// Copyright 2014-present Datadog, Inc.

package cpu

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemLogicalProcessorInformationSize is the size of
// systemLogicalProcessorInformation struct
const systemLogicalProcessorInformationSize = 24

func getSystemLogicalProcessorInformationSize() int {
	return systemLogicalProcessorInformationSize
}

func byteArrayToProcessorStruct(data []byte) (info systemLogicalProcessorInformation) {
	info.ProcessorMask = uintptr(binary.LittleEndian.Uint32(data))
	info.Relationship = int(binary.LittleEndian.Uint32(data[4:]))
	copy(info.dataunion[0:16], data[8:24])
	return
}

func computeCoresAndProcessors() (cpuInfo cpuInfo, err error) {
	var mod = windows.NewLazyDLL("kernel32.dll")
	var getProcInfo = mod.NewProc("GetLogicalProcessorInformation")
	var buflen uint32 = 0
	err = windows.Errno(0)
	// first, figure out how much we need
	status, _, err := getProcInfo.Call(uintptr(0),
		uintptr(unsafe.Pointer(&buflen)))
	if status == 0 {
		if err != errorInsufficientBuffer {
			// only error we're expecing here is insufficient buffer
			// anything else is a failure
			return
		}
	} else {
		// this shouldn't happen. Errno won't be set (because the function)
		// succeeded.  So just return something to indicate we've failed
		err = windows.Errno(2)
		return
	}
	buf := make([]byte, buflen)
	status, _, err = getProcInfo.Call(uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&buflen)))
	if status == 0 {
		return
	}
	// walk through each of the buffers

	for i := 0; uint32(i) < buflen; i += getSystemLogicalProcessorInformationSize() {
		info := byteArrayToProcessorStruct(buf[i : i+getSystemLogicalProcessorInformationSize()])

		switch info.Relationship {
		case RelationNumaNode:
			cpuInfo.numaNodeCount++

		case RelationProcessorCore:
			cpuInfo.corecount++
			cpuInfo.logicalcount += countBits(uint64(info.ProcessorMask))

		case RelationProcessorPackage:
			cpuInfo.pkgcount++
		}
	}
	return
}
