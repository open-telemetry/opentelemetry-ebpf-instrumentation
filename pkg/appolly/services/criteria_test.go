// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type yamlFile struct {
	Services   RegexDefinitionCriteria `yaml:"services"`
	Instrument GlobDefinitionCriteria  `yaml:"instrument"`
}

func TestYAMLParse_PathRegexp(t *testing.T) {
	inputFile := `
services:
  - name: foo
    exe_path: "^abc$"
`
	yf := yamlFile{}
	require.NoError(t, yaml.Unmarshal([]byte(inputFile), &yf))

	require.Len(t, yf.Services, 1)

	assert.True(t, yf.Services[0].Path.IsSet())
	assert.True(t, yf.Services[0].Path.MatchString("abc"))
	assert.False(t, yf.Services[0].Path.MatchString("cabc"))
	assert.False(t, yf.Services[0].Path.MatchString("abca"))

	assert.Zero(t, yf.Services[0].OpenPorts.Len())
}

func TestYAMLParse_PathRegexp_Errors(t *testing.T) {
	t.Run("wrong regex expression", func(t *testing.T) {
		require.Error(t, yaml.Unmarshal([]byte(`services:
  - exe_path: "{a\("`), &yamlFile{}))
	})
	t.Run("wrong regular pathregexp type", func(t *testing.T) {
		require.Error(t, yaml.Unmarshal([]byte(`services:
  - exe_path:
      other: kind`), &yamlFile{}))
	})
	t.Run("unknown attribute name", func(t *testing.T) {
		require.Error(t, yaml.Unmarshal([]byte(`services:
  - name: foo
    exe_path: "^abc$"
	chaca_chaca: foolss
`), &yamlFile{}))
	})
}

func TestYAMLParse_IntEnum(t *testing.T) {
	intEnumYAML := func(enum string) IntEnum {
		yf := yamlFile{}
		err := yaml.Unmarshal(fmt.Appendf(nil, "services:\n  - open_ports: %s\n", enum), &yf)
		require.NoError(t, err)
		require.Len(t, yf.Services, 1)
		assert.False(t, yf.Services[0].Path.IsSet())
		return yf.Services[0].OpenPorts
	}
	t.Run("single port number", func(t *testing.T) {
		pe := intEnumYAML("80")
		require.True(t, pe.Matches(80))
		require.False(t, pe.Matches(8))
		require.False(t, pe.Matches(79))
		require.False(t, pe.Matches(81))
		require.False(t, pe.Matches(8080))
	})
	t.Run("comma-separated port numbers", func(t *testing.T) {
		pe := intEnumYAML("80,8080")
		require.True(t, pe.Matches(80))
		require.True(t, pe.Matches(8080))
		require.False(t, pe.Matches(79))
		require.False(t, pe.Matches(8081))
	})
	t.Run("ranges", func(t *testing.T) {
		pe := intEnumYAML("8000-8999")
		require.True(t, pe.Matches(8000))
		require.True(t, pe.Matches(8999))
		require.True(t, pe.Matches(8080))
		require.False(t, pe.Matches(7999))
		require.False(t, pe.Matches(9000))
	})
	t.Run("merging ranges and single ports, and lots of spaces", func(t *testing.T) {
		pe := intEnumYAML("   80\t,   100 -200,443, 8000- 8999   ")
		require.True(t, pe.Matches(80))
		require.True(t, pe.Matches(100))
		require.True(t, pe.Matches(200))
		require.True(t, pe.Matches(443))
		require.True(t, pe.Matches(8000))
		require.True(t, pe.Matches(8999))
		require.True(t, pe.Matches(8080))
		require.False(t, pe.Matches(1))
		require.False(t, pe.Matches(90))
		require.False(t, pe.Matches(300))
		require.False(t, pe.Matches(1000))
		require.False(t, pe.Matches(15000))
	})
}

func TestYAMLParse_IntEnum_Errors(t *testing.T) {
	assertError := func(desc, enum string) {
		t.Run(desc, func(t *testing.T) {
			err := yaml.Unmarshal(fmt.Appendf(nil, "services:\n  - open_ports: %s\n", enum), &yamlFile{})
			require.Error(t, err)
		})
	}
	assertError("only comma", ",")
	assertError("only dash", "-")
	assertError("not a number", "1a")
	assertError("starting with comma", ",33")
	assertError("ending with comma", "33,")
	assertError("unfinished range", "32,15-")
	assertError("unstarted range", "12,-13")
	assertError("wrong symbols", "1,2,*3,4")
}

func TestYAMLParse_OtherAttrs(t *testing.T) {
	inputFile := `
services:
  - name: foo
    k8s_namespace: "aaa"
    k8s_pod_name: "abc"
    k8s_deployment_name: "bbb"
    k8s_replicaset_name: "bbc"
`
	yf := yamlFile{}
	require.NoError(t, yaml.Unmarshal([]byte(inputFile), &yf))

	require.Len(t, yf.Services, 1)

	other := yf.Services[0].Metadata
	assert.True(t, other["k8s_namespace"].MatchString("aaa"))
	assert.False(t, other["k8s_namespace"].MatchString("aa"))
	assert.True(t, other["k8s_pod_name"].MatchString("abc"))
	assert.False(t, other["k8s_pod_name"].MatchString("aa"))
	assert.True(t, other["k8s_deployment_name"].MatchString("bbb"))
	assert.False(t, other["k8s_deployment_name"].MatchString("aa"))
	assert.True(t, other["k8s_replicaset_name"].MatchString("bbc"))
	assert.False(t, other["k8s_replicaset_name"].MatchString("aa"))
}

func TestYAMLMarshal_CustomTypes(t *testing.T) {
	type tc struct {
		IntEnum    IntEnum
		Regex      RegexpAttr
		Glob       GlobAttr
		IntEnumPtr *IntEnum
		RegexPtr   *RegexpAttr
		GlobPtr    *GlobAttr
	}
	cases := &tc{
		IntEnum: IntEnum{
			Ranges: []IntRange{{Start: 80}, {Start: 8080, End: 8099}, {Start: 443}},
		},
		Regex: NewRegexp("^foo.*$"),
		Glob:  NewGlob("bar*"),
	}
	cases.RegexPtr = &cases.Regex
	cases.GlobPtr = &cases.Glob
	cases.IntEnumPtr = &cases.IntEnum

	yamlOut, err := yaml.Marshal(cases)
	require.NoError(t, err)
	assert.YAMLEq(t, `intenum: 80,8080-8099,443
regex: ^foo.*$
glob: bar*
intenumptr: 80,8080-8099,443
regexptr: ^foo.*$
globptr: bar*
`, string(yamlOut))
}

func TestRegexDefinitionCriteria_Validate(t *testing.T) {
	t.Run("empty criteria is valid", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with open_ports", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- open_ports: 80`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with exe_path", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- exe_path: "^/usr/bin/.*$"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with exe_path_regexp", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- exe_path_regexp: "^/usr/bin/.*$"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with languages", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- languages: "go|java"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with cmd_args", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- cmd_args: "--foo"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with metadata", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- k8s_namespace: "default"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with pod labels", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- k8s_pod_labels:\n    app: myapp"), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with pod annotations", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- k8s_pod_annotations:\n    sidecar: \"true\""), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("error when entry has no selection criteria", func(t *testing.T) {
		dc := RegexDefinitionCriteria{RegexSelector{Name: "my-service"}}
		err := dc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "index [0] should define at least one selection criteria")
	})
	t.Run("error on second empty entry", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- open_ports: 80\n- name: orphan"), &dc))
		err := dc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "index [1] should define at least one selection criteria")
	})
	t.Run("error on unknown metadata attribute", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- unknown_attr: "val"`), &dc))
		err := dc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown attribute")
		assert.Contains(t, err.Error(), "unknown_attr")
	})
	t.Run("valid with multiple entries", func(t *testing.T) {
		dc := RegexDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- open_ports: 80\n- languages: go\n- exe_path: \"^/bin/.*$\""), &dc))
		require.NoError(t, dc.Validate())
	})
}

func TestGlobDefinitionCriteria_Validate(t *testing.T) {
	t.Run("empty criteria is valid", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with open_ports", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- open_ports: 80`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with exe_path", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- exe_path: "/usr/bin/*"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with languages", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- languages: "{go,java}"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with metadata", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- k8s_namespace: "default"`), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with pod labels", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- k8s_pod_labels:\n    app: myapp"), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("valid with pod annotations", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- k8s_pod_annotations:\n    sidecar: \"true\""), &dc))
		require.NoError(t, dc.Validate())
	})
	t.Run("error when entry has no selection criteria", func(t *testing.T) {
		dc := GlobDefinitionCriteria{GlobAttributes{Name: "my-service"}}
		err := dc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "entry [0] should define at least one selection criteria")
	})
	t.Run("error on second empty entry", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- open_ports: 80\n- name: orphan"), &dc))
		err := dc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "entry [1] should define at least one selection criteria")
	})
	t.Run("error on unknown metadata attribute", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte(`- unknown_attr: "val"`), &dc))
		err := dc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown attribute")
		assert.Contains(t, err.Error(), "unknown_attr")
	})
	t.Run("valid with multiple entries", func(t *testing.T) {
		dc := GlobDefinitionCriteria{}
		require.NoError(t, yaml.Unmarshal([]byte("- open_ports: 80\n- languages: go\n- exe_path: \"/bin/*\""), &dc))
		require.NoError(t, dc.Validate())
	})
}

func TestDiscoveryConfig_Validate_CmdArgsOnlyRegexCriteria(t *testing.T) {
	t.Run("services accepts cmd_args-only regex selector", func(t *testing.T) {
		cfg := DiscoveryConfig{}
		require.NoError(t, yaml.Unmarshal([]byte("services:\n  - cmd_args: \"--foo\""), &cfg))
		require.NoError(t, cfg.Validate())
	})

	t.Run("exclude_services accepts cmd_args-only regex selector", func(t *testing.T) {
		cfg := DiscoveryConfig{}
		require.NoError(t, yaml.Unmarshal([]byte("exclude_services:\n  - cmd_args: \"--foo\""), &cfg))
		require.NoError(t, cfg.Validate())
	})
}

func TestYAMLParse_Language(t *testing.T) {
	inputFile := `
instrument:
  - name: foo
    languages: "{go,rust}"
`
	yf := yamlFile{}
	require.NoError(t, yaml.Unmarshal([]byte(inputFile), &yf))

	require.Len(t, yf.Instrument, 1)

	assert.True(t, yf.Instrument[0].Languages.IsSet())
	assert.True(t, yf.Instrument[0].Languages.MatchString("go"))
	assert.True(t, yf.Instrument[0].Languages.MatchString("rust"))
	assert.False(t, yf.Instrument[0].Languages.MatchString("java"))

	assert.Zero(t, yf.Instrument[0].OpenPorts.Len())
}

func TestYAMLParse_Language_RegEx(t *testing.T) {
	inputFile := `
services:
  - name: foo
    languages: "go|rust"
`
	yf := yamlFile{}
	require.NoError(t, yaml.Unmarshal([]byte(inputFile), &yf))

	require.Len(t, yf.Services, 1)

	assert.True(t, yf.Services[0].Languages.IsSet())
	assert.True(t, yf.Services[0].Languages.MatchString("go"))
	assert.True(t, yf.Services[0].Languages.MatchString("rust"))
	assert.False(t, yf.Services[0].Languages.MatchString("java"))

	assert.Zero(t, yf.Services[0].OpenPorts.Len())
}
