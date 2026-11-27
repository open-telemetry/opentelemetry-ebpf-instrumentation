// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runLintBPFIncludes(t *testing.T, rootDir string) (string, error) {
	t.Helper()

	cmd := exec.Command("./lint-bpf-includes.sh", rootDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestLintBPFIncludesRepo(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if out, err := runLintBPFIncludes(t, repoRoot); err != nil {
		t.Fatalf("expected repo to pass lint-bpf-includes.sh, got error %v:\n%s", err, out)
	}
}

func TestLintBPFIncludesFixtures(t *testing.T) {
	cases := []struct {
		name           string
		files          map[string]string
		wantErr        bool
		wantContain    []string
		wantNotContain []string
	}{
		{
			name: "allows shared and infra includes",
			files: map[string]string{
				"bpf/common/ok.h": strings.Join([]string{
					"#include <bpfcore/vmlinux.h>",
					"#include <common/go_addr_key.h>",
					"#include <logger/bpf_dbg.h>",
					"#include <maps/go_trace_map.h>",
					"#include <pid/pid_helpers.h>",
					"#include <shared/obi_ctx.h>",
				}, "\n"),
			},
			wantErr: false,
		},
		{
			name: "ignores commented-out tracer includes",
			files: map[string]string{
				"bpf/common/comments.h": strings.Join([]string{
					"// #include <gotracer/go_common.h>",
					"/* #include \"generictracer/k_tracer_defs.h\"",
					"#include \"../tpinjector/h2_parse.h\"",
					"*/",
					"#include <common/go_addr_key.h>",
				}, "\n"),
			},
			wantErr: false,
		},
		{
			name: "flags direct angle-bracket include in common",
			files: map[string]string{
				"bpf/common/bad.h": "#include <gotracer/go_common.h>\n",
			},
			wantErr:     true,
			wantContain: []string{"bpf/common/bad.h:1:", "gotracer/go_common.h"},
		},
		{
			name: "flags quoted include in maps",
			files: map[string]string{
				"bpf/maps/bad.h": "#include \"generictracer/types/foo.h\"\n",
			},
			wantErr:     true,
			wantContain: []string{"bpf/maps/bad.h:1:", "generictracer/types/foo.h"},
		},
		{
			name: "flags relative parent include in shared",
			files: map[string]string{
				"bpf/shared/bad.h": "#include \"../tpinjector/h2_parse.h\"\n",
			},
			wantErr:     true,
			wantContain: []string{"bpf/shared/bad.h:1:", "../tpinjector/h2_parse.h"},
		},
		{
			name: "flags interior dotdot and bpf-prefixed tracer includes",
			files: map[string]string{
				"bpf/common/tricky.h": strings.Join([]string{
					"#include <common/../gotracer/go_common.h>",
					"#include \"../../bpf/generictracer/k_tracer_defs.h\"",
				}, "\n"),
			},
			wantErr: true,
			wantContain: []string{
				"bpf/common/tricky.h:1:",
				"common/../gotracer/go_common.h",
				"bpf/common/tricky.h:2:",
				"../../bpf/generictracer/k_tracer_defs.h",
			},
		},
		{
			name: "does not let slash-star inside line comment mask later include",
			files: map[string]string{
				"bpf/common/line_comment_glob.h": strings.Join([]string{
					"// applies to bpf/generictracer/*",
					"#include <gotracer/go_common.h>",
				}, "\n"),
			},
			wantErr:     true,
			wantContain: []string{"bpf/common/line_comment_glob.h:2:", "gotracer/go_common.h"},
		},
		{
			name: "does not let double-slash inside block comment mask include on same line",
			files: map[string]string{
				"bpf/common/block_comment_slashes.h": "/* // */ #include <gotracer/go_common.h>\n",
			},
			wantErr:     true,
			wantContain: []string{"bpf/common/block_comment_slashes.h:1:", "gotracer/go_common.h"},
		},
		{
			name: "does not let comment markers inside string literals mask later include",
			files: map[string]string{
				"bpf/common/string_literal.h": strings.Join([]string{
					`#define HTTP_ACCEPT "*/*"`,
					`#define ESCAPED_QUOTE "\"/*"`,
					"#include <gotracer/go_common.h>",
				}, "\n"),
			},
			wantErr:     true,
			wantContain: []string{"bpf/common/string_literal.h:3:", "gotracer/go_common.h"},
		},
		{
			name: "handles escaped backslash before closing quote and char literals",
			files: map[string]string{
				"bpf/common/escapes_and_chars.h": strings.Join([]string{
					`#define DIR "foo\\" /*`,
					"#include <gotracer/go_common.h>",
					"*/",
					`const char dq = '"';`,
					`const char sq = '\'';`,
					`#define CHAR_SLASH '/*'`,
					"#include <generictracer/k_tracer_defs.h>",
				}, "\n"),
			},
			wantErr:        true,
			wantContain:    []string{"bpf/common/escapes_and_chars.h:7:", "generictracer/k_tracer_defs.h"},
			wantNotContain: []string{"gotracer/go_common.h"},
		},
		{
			name: "handles backslash-continued multiline string literal with comment markers",
			files: map[string]string{
				"bpf/common/multiline_string.h": strings.Join([]string{
					`const char *s = "hello \`,
					`/* still inside string */";`,
					"#include <gotracer/go_common.h>",
				}, "\n"),
			},
			wantErr:     true,
			wantContain: []string{"bpf/common/multiline_string.h:3:", "gotracer/go_common.h"},
		},
		{
			name: "flags tracer includes in pid and logger directories",
			files: map[string]string{
				"bpf/pid/bad.h":    "#include <gotracer/go_common.h>\n",
				"bpf/logger/bad.h": "#include <generictracer/k_tracer_defs.h>\n",
			},
			wantErr: true,
			wantContain: []string{
				"bpf/pid/bad.h:1:",
				"bpf/logger/bad.h:1:",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{
				"bpf/common",
				"bpf/logger",
				"bpf/maps",
				"bpf/pid",
				"bpf/shared",
				"bpf/gotracer",
				"bpf/generictracer",
				"bpf/tpinjector",
			} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", dir, err)
				}
			}
			for relPath, content := range tc.files {
				full := filepath.Join(root, relPath)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatalf("mkdir parent for %s: %v", relPath, err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatalf("write %s: %v", relPath, err)
				}
			}

			out, err := runLintBPFIncludes(t, root)
			if tc.wantErr && err == nil {
				t.Fatalf("expected lint error, got success:\n%s", out)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected success, got error %v:\n%s", err, out)
			}
			for _, sub := range tc.wantContain {
				if !strings.Contains(out, sub) {
					t.Errorf("expected output to contain %q, got:\n%s", sub, out)
				}
			}
			for _, sub := range tc.wantNotContain {
				if strings.Contains(out, sub) {
					t.Errorf("expected output NOT to contain %q, got:\n%s", sub, out)
				}
			}
		})
	}
}
