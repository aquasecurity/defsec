package dockerfile

import (
	"bytes"
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/rego/schemas"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/rego"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

const DS006PolicyWithDockerfileSchema = `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["dockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS006
#   avd_id: AVD-DS-0006
#   severity: CRITICAL
#   short_code: no-self-referencing-copy-from
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006

import data.lib.docker

get_alias_from_copy[output] {
	copies := docker.stage_copies[stage]

	copy := copies[_]
	flag := copy.Flags[_]
	contains(flag, "--from=")
	parts := split(flag, "=")

	is_alias_current_from_alias(stage.Name, parts[1])
	args := parts[1]
	output := {
		"args": args,
		"cmd": copy,
	}
}

is_alias_current_from_alias(current_name, current_alias) = allow {
	current_name_lower := lower(current_name)
	current_alias_lower := lower(current_alias)

	#expecting stage name as "myimage:tag as dep"
	[_, alias] := regex.split(` + "`\\s+as\\s+`" + `, current_name_lower)

	alias == current_alias

	allow = true
}

deny[res] {
	output := get_alias_from_copy[_]
	msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
	res := result.new(msg, output.cmd)
}
`

const DS006PolicyWithMyFancyDockerfileSchema = `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["myfancydockerfile"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS006
#   avd_id: AVD-DS-0006
#   severity: CRITICAL
#   short_code: no-self-referencing-copy-from
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006

import data.lib.docker

get_alias_from_copy[output] {
copies := docker.stage_copies[stage]

copy := copies[_]
flag := copy.Flags[_]
contains(flag, "--from=")
parts := split(flag, "=")

is_alias_current_from_alias(stage.Name, parts[1])
args := parts[1]
output := {
"args": args,
"cmd": copy,
}
}

is_alias_current_from_alias(current_name, current_alias) = allow {
current_name_lower := lower(current_name)
current_alias_lower := lower(current_alias)

#expecting stage name as "myimage:tag as dep"
[_, alias] := regex.split(` + "`\\s+as\\s+`" + `, current_name_lower)

alias == current_alias

allow = true
}

deny[res] {
output := get_alias_from_copy[_]
msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
res := result.new(msg, output.cmd)
}
`

const DS006PolicyWithOldSchemaSelector = `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["input"]
# related_resources:
# - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS006
#   avd_id: AVD-DS-0006
#   severity: CRITICAL
#   short_code: no-self-referencing-copy-from
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006

import data.lib.docker

get_alias_from_copy[output] {
	copies := docker.stage_copies[stage]

	copy := copies[_]
	flag := copy.Flags[_]
	contains(flag, "--from=")
	parts := split(flag, "=")

	is_alias_current_from_alias(stage.Name, parts[1])
	args := parts[1]
	output := {
		"args": args,
		"cmd": copy,
	}
}

is_alias_current_from_alias(current_name, current_alias) = allow {
	current_name_lower := lower(current_name)
	current_alias_lower := lower(current_alias)

	#expecting stage name as "myimage:tag as dep"
	[_, alias] := regex.split(` + "`\\s+as\\s+`" + `, current_name_lower)

	alias == current_alias

	allow = true
}

deny[res] {
	output := get_alias_from_copy[_]
	msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
	res := result.new(msg, output.cmd)
}
`
const DS006LegacyWithOldStyleMetadata = `package builtin.dockerfile.DS006

__rego_metadata__ := {
	"id": "DS006",
	"avd_id": "AVD-DS-0006",
	"title": "COPY '--from' referring to the current image",
	"short_code": "no-self-referencing-copy-from",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
	"recommended_actions": "Change the '--from' so that it will not refer to itself",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	res := {
		"msg": "oh no",
		"filepath": "code/Dockerfile",
		"startline": 1,
		"endline": 1,
	}
}`

func Test_BasicScanLegacyRegoMetadata(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"/code/Dockerfile": `FROM ubuntu
USER root
`,
		"/rules/rule.rego": DS006LegacyWithOldStyleMetadata,
	})

	scanner := NewScanner(options.ScannerWithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]
	metadata := failure.Metadata()
	assert.Equal(t, 1, metadata.Range().GetStartLine())
	assert.Equal(t, 1, metadata.Range().GetEndLine())
	assert.Equal(t, "code/Dockerfile", metadata.Range().GetFilename())

	assert.Equal(
		t,
		scan.Rule{
			AVDID:          "AVD-DS-0006",
			Aliases:        []string{"DS006"},
			ShortCode:      "no-self-referencing-copy-from",
			Summary:        "COPY '--from' referring to the current image",
			Explanation:    "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
			Impact:         "",
			Resolution:     "Change the '--from' so that it will not refer to itself",
			Provider:       "dockerfile",
			Service:        "general",
			Links:          []string{"https://docs.docker.com/develop/develop-images/multistage-build/"},
			Severity:       "CRITICAL",
			Terraform:      &scan.EngineMetadata{},
			CloudFormation: &scan.EngineMetadata{},
			CustomChecks: scan.CustomChecks{
				Terraform: (*scan.TerraformCustomCheck)(nil)},
			RegoPackage: "data.builtin.dockerfile.DS006",
			Frameworks:  map[framework.Framework][]string{},
		},
		results.GetFailed()[0].Rule(),
	)

	actualCode, err := results.GetFailed()[0].GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     1,
			Content:    "FROM ubuntu",
			IsCause:    true,
			FirstCause: true,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

func Test_BasicScanNewRegoMetadata(t *testing.T) {
	var testCases = []struct {
		name              string
		inputRegoPolicy   string
		expectedError     string
		expectedTraceLogs string
	}{
		{
			name:            "old schema selector schema.input",
			inputRegoPolicy: DS006PolicyWithOldSchemaSelector,
			expectedTraceLogs: `REGO INPUT:
{
  "path": "code/Dockerfile",
  "contents": {
    "Stages": [
      {
        "Commands": [
          {
            "Cmd": "from",
            "EndLine": 1,
            "Flags": [],
            "JSON": false,
            "Original": "FROM golang:1.7.3 as dep",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 1,
            "SubCmd": "",
            "Value": [
              "golang:1.7.3",
              "as",
              "dep"
            ]
          },
          {
            "Cmd": "copy",
            "EndLine": 2,
            "Flags": [
              "--from=dep"
            ],
            "JSON": false,
            "Original": "COPY --from=dep /binary /",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 2,
            "SubCmd": "",
            "Value": [
              "/binary",
              "/"
            ]
          }
        ],
        "Name": "golang:1.7.3 as dep"
      }
    ]
  }
}
END REGO INPUT

Enter data.builtin.dockerfile.DS006.deny = _
| Eval data.builtin.dockerfile.DS006.deny = _
| Index data.builtin.dockerfile.DS006.deny (matched 1 rule)
| Enter data.builtin.dockerfile.DS006.deny
| | Eval output = data.builtin.dockerfile.DS006.get_alias_from_copy[_]
| | Index data.builtin.dockerfile.DS006.get_alias_from_copy (matched 1 rule)
| | Enter data.builtin.dockerfile.DS006.get_alias_from_copy
| | | Eval copies = data.lib.docker.stage_copies[stage]
| | | Index data.lib.docker.stage_copies (matched 1 rule)
| | | Enter data.lib.docker.stage_copies
| | | | Eval stage = input.Stages[_]
| | | | Eval copies = [copy | copy = stage.Commands[_]; copy.Cmd = "copy"]
| | | | Enter copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | | Eval copy = stage.Commands[_]
| | | | | Eval copy.Cmd = "copy"
| | | | | Fail copy.Cmd = "copy"
| | | | | Redo copy = stage.Commands[_]
| | | | | Eval copy.Cmd = "copy"
| | | | | Exit copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | Redo copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | | Redo copy.Cmd = "copy"
| | | | | Redo copy = stage.Commands[_]
| | | | Exit data.lib.docker.stage_copies
| | | Redo data.lib.docker.stage_copies
| | | | Redo copies = [copy | copy = stage.Commands[_]; copy.Cmd = "copy"]
| | | | Redo stage = input.Stages[_]
| | | Eval copy = copies[_]
| | | Eval flag = copy.Flags[_]
| | | Eval contains(flag, "--from=")
| | | Eval split(flag, "=", command)
| | | Eval parts = command
| | | Eval x = stage.Name
| | | Eval k = parts[1]
| | | Eval data.builtin.dockerfile.DS006.is_alias_current_from_alias(x, k)
| | | Index data.builtin.dockerfile.DS006.is_alias_current_from_alias (matched 1 rule)
| | | Enter data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | | Eval lower(current_name, flag)
| | | | Eval current_name_lower = flag
| | | | Eval lower(current_alias, container)
| | | | Eval current_alias_lower = container
| | | | Eval regex.split("\\s+as\\s+", current_name_lower, container)
| | | | Eval [_, alias] = container
| | | | Eval alias = current_alias
| | | | Eval allow = true
| | | | Exit data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | Eval args = parts[1]
| | | Eval output = {"args": args, "cmd": copy}
| | | Exit data.builtin.dockerfile.DS006.get_alias_from_copy
| | Redo data.builtin.dockerfile.DS006.get_alias_from_copy
| | | Redo output = {"args": args, "cmd": copy}
| | | Redo args = parts[1]
| | | Redo data.builtin.dockerfile.DS006.is_alias_current_from_alias(x, k)
| | | Redo data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | | Redo allow = true
| | | | Redo alias = current_alias
| | | | Redo [_, alias] = container
| | | | Redo regex.split("\\s+as\\s+", current_name_lower, container)
| | | | Redo current_alias_lower = container
| | | | Redo lower(current_alias, container)
| | | | Redo current_name_lower = flag
| | | | Redo lower(current_name, flag)
| | | Redo k = parts[1]
| | | Redo x = stage.Name
| | | Redo parts = command
| | | Redo split(flag, "=", command)
| | | Redo contains(flag, "--from=")
| | | Redo flag = copy.Flags[_]
| | | Redo copy = copies[_]
| | | Redo copies = data.lib.docker.stage_copies[stage]
| | Eval copies = output.args
| | Eval sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [copies], container)
| | Eval msg = container
| | Eval copy = output.cmd
| | Eval result.new(msg, copy, container)
| | Eval res = container
| | Exit data.builtin.dockerfile.DS006.deny
| Redo data.builtin.dockerfile.DS006.deny
| | Redo res = container
| | Redo result.new(msg, copy, container)
| | Redo copy = output.cmd
| | Redo msg = container
| | Redo sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [copies], container)
| | Redo copies = output.args
| | Redo output = data.builtin.dockerfile.DS006.get_alias_from_copy[_]
| Exit data.builtin.dockerfile.DS006.deny = _
Redo data.builtin.dockerfile.DS006.deny = _
| Redo data.builtin.dockerfile.DS006.deny = _
REGO RESULTSET:
[
  {
    "expressions": [
      {
        "value": [
          {
            "endline": 2,
            "explicit": false,
            "filepath": "code/Dockerfile",
            "fskey": "",
            "managed": true,
            "msg": "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself",
            "resource": "",
            "startline": 2
          }
        ],
        "text": "data.builtin.dockerfile.DS006.deny",
        "location": {
          "row": 1,
          "col": 1
        }
      }
    ]
  }
]
END REGO RESULTSET

`,
		},
		{
			name:            "new schema selector schema.dockerfile",
			inputRegoPolicy: DS006PolicyWithDockerfileSchema,
			expectedTraceLogs: `REGO INPUT:
{
  "path": "code/Dockerfile",
  "contents": {
    "Stages": [
      {
        "Commands": [
          {
            "Cmd": "from",
            "EndLine": 1,
            "Flags": [],
            "JSON": false,
            "Original": "FROM golang:1.7.3 as dep",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 1,
            "SubCmd": "",
            "Value": [
              "golang:1.7.3",
              "as",
              "dep"
            ]
          },
          {
            "Cmd": "copy",
            "EndLine": 2,
            "Flags": [
              "--from=dep"
            ],
            "JSON": false,
            "Original": "COPY --from=dep /binary /",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 2,
            "SubCmd": "",
            "Value": [
              "/binary",
              "/"
            ]
          }
        ],
        "Name": "golang:1.7.3 as dep"
      }
    ]
  }
}
END REGO INPUT

Enter data.builtin.dockerfile.DS006.deny = _
| Eval data.builtin.dockerfile.DS006.deny = _
| Index data.builtin.dockerfile.DS006.deny (matched 1 rule)
| Enter data.builtin.dockerfile.DS006.deny
| | Eval output = data.builtin.dockerfile.DS006.get_alias_from_copy[_]
| | Index data.builtin.dockerfile.DS006.get_alias_from_copy (matched 1 rule)
| | Enter data.builtin.dockerfile.DS006.get_alias_from_copy
| | | Eval copies = data.lib.docker.stage_copies[stage]
| | | Index data.lib.docker.stage_copies (matched 1 rule)
| | | Enter data.lib.docker.stage_copies
| | | | Eval stage = input.Stages[_]
| | | | Eval copies = [copy | copy = stage.Commands[_]; copy.Cmd = "copy"]
| | | | Enter copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | | Eval copy = stage.Commands[_]
| | | | | Eval copy.Cmd = "copy"
| | | | | Fail copy.Cmd = "copy"
| | | | | Redo copy = stage.Commands[_]
| | | | | Eval copy.Cmd = "copy"
| | | | | Exit copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | Redo copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | | Redo copy.Cmd = "copy"
| | | | | Redo copy = stage.Commands[_]
| | | | Exit data.lib.docker.stage_copies
| | | Redo data.lib.docker.stage_copies
| | | | Redo copies = [copy | copy = stage.Commands[_]; copy.Cmd = "copy"]
| | | | Redo stage = input.Stages[_]
| | | Eval copy = copies[_]
| | | Eval flag = copy.Flags[_]
| | | Eval contains(flag, "--from=")
| | | Eval split(flag, "=", __local68__)
| | | Eval parts = __local68__
| | | Eval __local89__ = stage.Name
| | | Eval __local90__ = parts[1]
| | | Eval data.builtin.dockerfile.DS006.is_alias_current_from_alias(__local89__, __local90__)
| | | Index data.builtin.dockerfile.DS006.is_alias_current_from_alias (matched 1 rule)
| | | Enter data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | | Eval lower(current_name, __local69__)
| | | | Eval current_name_lower = __local69__
| | | | Eval lower(current_alias, __local70__)
| | | | Eval current_alias_lower = __local70__
| | | | Eval regex.split("\\s+as\\s+", current_name_lower, __local71__)
| | | | Eval [_, alias] = __local71__
| | | | Eval alias = current_alias
| | | | Eval allow = true
| | | | Exit data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | Eval args = parts[1]
| | | Eval output = {"args": args, "cmd": copy}
| | | Exit data.builtin.dockerfile.DS006.get_alias_from_copy
| | Redo data.builtin.dockerfile.DS006.get_alias_from_copy
| | | Redo output = {"args": args, "cmd": copy}
| | | Redo args = parts[1]
| | | Redo data.builtin.dockerfile.DS006.is_alias_current_from_alias(__local89__, __local90__)
| | | Redo data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | | Redo allow = true
| | | | Redo alias = current_alias
| | | | Redo [_, alias] = __local71__
| | | | Redo regex.split("\\s+as\\s+", current_name_lower, __local71__)
| | | | Redo current_alias_lower = __local70__
| | | | Redo lower(current_alias, __local70__)
| | | | Redo current_name_lower = __local69__
| | | | Redo lower(current_name, __local69__)
| | | Redo __local90__ = parts[1]
| | | Redo __local89__ = stage.Name
| | | Redo parts = __local68__
| | | Redo split(flag, "=", __local68__)
| | | Redo contains(flag, "--from=")
| | | Redo flag = copy.Flags[_]
| | | Redo copy = copies[_]
| | | Redo copies = data.lib.docker.stage_copies[stage]
| | Eval __local91__ = output.args
| | Eval sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [__local91__], __local72__)
| | Eval msg = __local72__
| | Eval __local92__ = output.cmd
| | Eval result.new(msg, __local92__, __local73__)
| | Eval res = __local73__
| | Exit data.builtin.dockerfile.DS006.deny
| Redo data.builtin.dockerfile.DS006.deny
| | Redo res = __local73__
| | Redo result.new(msg, __local92__, __local73__)
| | Redo __local92__ = output.cmd
| | Redo msg = __local72__
| | Redo sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [__local91__], __local72__)
| | Redo __local91__ = output.args
| | Redo output = data.builtin.dockerfile.DS006.get_alias_from_copy[_]
| Exit data.builtin.dockerfile.DS006.deny = _
Redo data.builtin.dockerfile.DS006.deny = _
| Redo data.builtin.dockerfile.DS006.deny = _
REGO RESULTSET:
[
  {
    "expressions": [
      {
        "value": [
          {
            "endline": 2,
            "explicit": false,
            "filepath": "code/Dockerfile",
            "fskey": "",
            "managed": true,
            "msg": "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself",
            "resource": "",
            "startline": 2
          }
        ],
        "text": "data.builtin.dockerfile.DS006.deny",
        "location": {
          "row": 1,
          "col": 1
        }
      }
    ]
  }
]
END REGO RESULTSET

`,
		},
		{
			name:            "new schema selector with custom schema.myfancydockerfile",
			inputRegoPolicy: DS006PolicyWithMyFancyDockerfileSchema,
			expectedTraceLogs: `REGO INPUT:
{
  "path": "code/Dockerfile",
  "contents": {
    "Stages": [
      {
        "Commands": [
          {
            "Cmd": "from",
            "EndLine": 1,
            "Flags": [],
            "JSON": false,
            "Original": "FROM golang:1.7.3 as dep",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 1,
            "SubCmd": "",
            "Value": [
              "golang:1.7.3",
              "as",
              "dep"
            ]
          },
          {
            "Cmd": "copy",
            "EndLine": 2,
            "Flags": [
              "--from=dep"
            ],
            "JSON": false,
            "Original": "COPY --from=dep /binary /",
            "Path": "code/Dockerfile",
            "Stage": 0,
            "StartLine": 2,
            "SubCmd": "",
            "Value": [
              "/binary",
              "/"
            ]
          }
        ],
        "Name": "golang:1.7.3 as dep"
      }
    ]
  }
}
END REGO INPUT

Enter data.builtin.dockerfile.DS006.deny = _
| Eval data.builtin.dockerfile.DS006.deny = _
| Index data.builtin.dockerfile.DS006.deny (matched 1 rule)
| Enter data.builtin.dockerfile.DS006.deny
| | Eval output = data.builtin.dockerfile.DS006.get_alias_from_copy[_]
| | Index data.builtin.dockerfile.DS006.get_alias_from_copy (matched 1 rule)
| | Enter data.builtin.dockerfile.DS006.get_alias_from_copy
| | | Eval copies = data.lib.docker.stage_copies[stage]
| | | Index data.lib.docker.stage_copies (matched 1 rule)
| | | Enter data.lib.docker.stage_copies
| | | | Eval stage = input.Stages[_]
| | | | Eval copies = [copy | copy = stage.Commands[_]; copy.Cmd = "copy"]
| | | | Enter copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | | Eval copy = stage.Commands[_]
| | | | | Eval copy.Cmd = "copy"
| | | | | Fail copy.Cmd = "copy"
| | | | | Redo copy = stage.Commands[_]
| | | | | Eval copy.Cmd = "copy"
| | | | | Exit copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | Redo copy = stage.Commands[_]; copy.Cmd = "copy"
| | | | | Redo copy.Cmd = "copy"
| | | | | Redo copy = stage.Commands[_]
| | | | Exit data.lib.docker.stage_copies
| | | Redo data.lib.docker.stage_copies
| | | | Redo copies = [copy | copy = stage.Commands[_]; copy.Cmd = "copy"]
| | | | Redo stage = input.Stages[_]
| | | Eval copy = copies[_]
| | | Eval flag = copy.Flags[_]
| | | Eval contains(flag, "--from=")
| | | Eval split(flag, "=", __local68__)
| | | Eval parts = __local68__
| | | Eval __local89__ = stage.Name
| | | Eval __local90__ = parts[1]
| | | Eval data.builtin.dockerfile.DS006.is_alias_current_from_alias(__local89__, __local90__)
| | | Index data.builtin.dockerfile.DS006.is_alias_current_from_alias (matched 1 rule)
| | | Enter data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | | Eval lower(current_name, __local69__)
| | | | Eval current_name_lower = __local69__
| | | | Eval lower(current_alias, __local70__)
| | | | Eval current_alias_lower = __local70__
| | | | Eval regex.split("\\s+as\\s+", current_name_lower, __local71__)
| | | | Eval [_, alias] = __local71__
| | | | Eval alias = current_alias
| | | | Eval allow = true
| | | | Exit data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | Eval args = parts[1]
| | | Eval output = {"args": args, "cmd": copy}
| | | Exit data.builtin.dockerfile.DS006.get_alias_from_copy
| | Redo data.builtin.dockerfile.DS006.get_alias_from_copy
| | | Redo output = {"args": args, "cmd": copy}
| | | Redo args = parts[1]
| | | Redo data.builtin.dockerfile.DS006.is_alias_current_from_alias(__local89__, __local90__)
| | | Redo data.builtin.dockerfile.DS006.is_alias_current_from_alias
| | | | Redo allow = true
| | | | Redo alias = current_alias
| | | | Redo [_, alias] = __local71__
| | | | Redo regex.split("\\s+as\\s+", current_name_lower, __local71__)
| | | | Redo current_alias_lower = __local70__
| | | | Redo lower(current_alias, __local70__)
| | | | Redo current_name_lower = __local69__
| | | | Redo lower(current_name, __local69__)
| | | Redo __local90__ = parts[1]
| | | Redo __local89__ = stage.Name
| | | Redo parts = __local68__
| | | Redo split(flag, "=", __local68__)
| | | Redo contains(flag, "--from=")
| | | Redo flag = copy.Flags[_]
| | | Redo copy = copies[_]
| | | Redo copies = data.lib.docker.stage_copies[stage]
| | Eval __local91__ = output.args
| | Eval sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [__local91__], __local72__)
| | Eval msg = __local72__
| | Eval __local92__ = output.cmd
| | Eval result.new(msg, __local92__, __local73__)
| | Eval res = __local73__
| | Exit data.builtin.dockerfile.DS006.deny
| Redo data.builtin.dockerfile.DS006.deny
| | Redo res = __local73__
| | Redo result.new(msg, __local92__, __local73__)
| | Redo __local92__ = output.cmd
| | Redo msg = __local72__
| | Redo sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [__local91__], __local72__)
| | Redo __local91__ = output.args
| | Redo output = data.builtin.dockerfile.DS006.get_alias_from_copy[_]
| Exit data.builtin.dockerfile.DS006.deny = _
Redo data.builtin.dockerfile.DS006.deny = _
| Redo data.builtin.dockerfile.DS006.deny = _
REGO RESULTSET:
[
  {
    "expressions": [
      {
        "value": [
          {
            "endline": 2,
            "explicit": false,
            "filepath": "code/Dockerfile",
            "fskey": "",
            "managed": true,
            "msg": "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself",
            "resource": "",
            "startline": 2
          }
        ],
        "text": "data.builtin.dockerfile.DS006.deny",
        "location": {
          "row": 1,
          "col": 1
        }
      }
    ]
  }
]
END REGO RESULTSET

`,
		},
		{
			name: "new schema selector but invalid",
			inputRegoPolicy: `# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
# - input: schema["spooky-schema"]
# custom:
#   input:
#     selector:
#     - type: dockerfile
package builtin.dockerfile.DS006
deny[res]{
	res := true
}`,
			expectedError: `1 error occurred: rules/rule.rego:12: rego_type_error: undefined schema: schema["spooky-schema"]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			regoMap := make(map[string]string)
			libs, err := rego.RecurseEmbeddedModules(rules.EmbeddedLibraryFileSystem, ".")
			require.NoError(t, err)
			for name, library := range libs {
				regoMap["/rules/"+name] = library.String()
			}
			regoMap["/code/Dockerfile"] = `FROM golang:1.7.3 as dep
COPY --from=dep /binary /`
			regoMap["/rules/rule.rego"] = tc.inputRegoPolicy
			regoMap["/rules/schemas/myfancydockerfile.json"] = string(schemas.Dockerfile) // just use the same for testing
			fs := testutil.CreateFS(t, regoMap)

			var traceBuf bytes.Buffer
			var debugBuf bytes.Buffer

			scanner := NewScanner(
				options.ScannerWithPolicyDirs("rules"),
				options.ScannerWithTrace(&traceBuf),
				options.ScannerWithDebug(&debugBuf),
			)

			results, err := scanner.ScanFS(context.TODO(), fs, "code")
			if tc.expectedError != "" {
				require.Equal(t, tc.expectedError, err.Error(), tc.name)
			} else {
				require.NoError(t, err)
				require.Len(t, results.GetFailed(), 1)

				failure := results.GetFailed()[0]
				metadata := failure.Metadata()
				assert.Equal(t, 2, metadata.Range().GetStartLine())
				assert.Equal(t, 2, metadata.Range().GetEndLine())
				assert.Equal(t, "code/Dockerfile", metadata.Range().GetFilename())

				assert.Equal(
					t,
					scan.Rule{
						AVDID:          "AVD-DS-0006",
						Aliases:        []string{"DS006"},
						ShortCode:      "no-self-referencing-copy-from",
						Summary:        "COPY '--from' referring to the current image",
						Explanation:    "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
						Impact:         "",
						Resolution:     "Change the '--from' so that it will not refer to itself",
						Provider:       "dockerfile",
						Service:        "general",
						Links:          []string{"https://docs.docker.com/develop/develop-images/multistage-build/"},
						Severity:       "CRITICAL",
						Terraform:      &scan.EngineMetadata{},
						CloudFormation: &scan.EngineMetadata{},
						CustomChecks: scan.CustomChecks{
							Terraform: (*scan.TerraformCustomCheck)(nil)},
						RegoPackage: "data.builtin.dockerfile.DS006",
						Frameworks:  map[framework.Framework][]string{},
					},
					results.GetFailed()[0].Rule(),
				)

				actualCode, err := results.GetFailed()[0].GetCode()
				require.NoError(t, err)
				for i := range actualCode.Lines {
					actualCode.Lines[i].Highlighted = ""
				}
				assert.Equal(t, []scan.Line{
					{
						Number:     2,
						Content:    "COPY --from=dep /binary /",
						IsCause:    true,
						FirstCause: true,
						LastCause:  true,
						Annotation: "",
					},
				}, actualCode.Lines)

				// assert logs
				assert.Equal(t, tc.expectedTraceLogs, traceBuf.String(), tc.name)
			}
		})
	}

}
