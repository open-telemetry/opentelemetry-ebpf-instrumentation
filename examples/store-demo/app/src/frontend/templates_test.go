// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var legacyFrontendAssetBrand = regexp.MustCompile(`Hip` + `ster|Cym` + `bal`)

func TestHeaderUsesOBIStoreBrand(t *testing.T) {
	output := renderTemplateForTest(t, "header")

	for _, want := range []string{
		"<title>OBI Store</title>",
		`src="/static/icons/OBI_Store_NavLogo.svg"`,
		`alt="OBI Store"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("rendered header does not contain %q", want)
		}
	}
}

func TestAssistantUsesOBIStoreBrand(t *testing.T) {
	output := renderTemplateForTest(t, "assistant")

	if !strings.Contains(output, "Hi, I'm the OBI Store assistant.") {
		t.Fatal("rendered assistant greeting does not use OBI Store branding")
	}
}

func TestFrontendAssetsAreDebranded(t *testing.T) {
	for _, root := range []string{"static", "templates"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if legacyFrontendAssetBrand.MatchString(path) {
				t.Errorf("frontend asset path still uses legacy brand: %s", path)
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if legacyFrontendAssetBrand.Match(content) {
				t.Errorf("frontend asset content still uses legacy brand: %s", path)
			}

			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

func renderTemplateForTest(t *testing.T, name string) string {
	t.Helper()

	var output bytes.Buffer
	data := map[string]interface{}{
		"baseUrl": "",
	}

	if err := templates.ExecuteTemplate(&output, name, data); err != nil {
		t.Fatalf("render %s template: %v", name, err)
	}

	return output.String()
}
