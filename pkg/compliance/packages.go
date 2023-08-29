// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/textproto"
	"os"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"golang.org/x/exp/slices"
)

type pkg struct {
	Name    string
	Version string
	Arch    string
}

func findApkPackage(path string, names []string) *pkg {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		var p pkg
		if len(l) < 2 {
			if p.Name != "" && slices.Contains(names, p.Name) {
				return &p
			}
			p = pkg{}
			continue
		}
		pre, suf := l[2:], l[2:]
		switch pre {
		case "P:":
			p.Name = suf
		case "V:":
			p.Version = suf
		case "A:":
			p.Arch = suf
		}
	}
	return nil
}

func findDpkgPackage(path string, names []string) *pkg {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if n := bytes.Index(data, []byte("\n\n")); n != -1 {
			return n + 2, data[0:n], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return
	})

	for scanner.Scan() {
		b := scanner.Bytes()
		reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
		header, err := reader.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil
		}
		name := header.Get("Package")
		if slices.Contains(names, name) {
			return &pkg{
				Name:    name,
				Version: header.Get("Version"),
				Arch:    header.Get("Architecture"),
			}
		}
	}

	return nil
}

func findRpmPackage(path string, names []string) *pkg {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	db, err := rpmdb.Open(path)
	if err != nil {
		return nil
	}
	for _, name := range names {
		p, err := db.Package(name)
		if err != nil {
			continue
		}
		return &pkg{
			Name:    p.Name,
			Version: p.Version,
			Arch:    p.Arch,
		}
	}
	return nil
}
