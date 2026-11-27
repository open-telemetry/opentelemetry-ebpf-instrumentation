// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/buildinfo"
	"net"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/net/publicsuffix"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

// ResolveServiceMetadata infers a missing service namespace from the main module.
func ResolveServiceMetadata(fi *exec.FileInfo) error {
	if fi.ServiceAttrs().UID.Namespace != "" {
		return nil
	}
	f, err := fi.OpenExecutable()
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := buildinfo.Read(f)
	if err != nil {
		return err
	}
	fi.SetAutoServiceNamespace(goModuleNamespace(info.Main.Path))
	return nil
}

func goModuleNamespace(path string) string {
	if module.CheckPath(path) != nil {
		return ""
	}
	host, rest, _ := strings.Cut(path, "/")
	switch host {
	case "git.sr.ht":
		var ok bool
		rest, ok = strings.CutPrefix(rest, "~")
		if !ok {
			return ""
		}
		fallthrough
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitea.com", "gitee.com":
		owner, _, hasRepo := strings.Cut(rest, "/")
		if hasRepo {
			return owner
		}
		return ""
	case "gopkg.in":
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	owner, _, _ := strings.Cut(domain, ".")
	return owner
}
