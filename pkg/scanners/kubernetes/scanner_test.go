package kubernetes

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_BasicScan(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/example.yaml": `
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`,
		"/rules/rule.rego": `
package builtin.kubernetes.KSV011

import data.lib.kubernetes
import data.lib.utils

default failLimitsCPU = false

__rego_metadata__ := {
	"id": "KSV011",
	"avd_id": "AVD-KSV-0011",
	"title": "CPU not limited",
	"short_code": "limit-cpu",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enforcing CPU limits prevents DoS via resource exhaustion.",
	"recommended_actions": "Set a limit value under 'containers[].resources.limits.cpu'.",
	"url": "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getLimitsCPUContainers returns all containers which have set resources.limits.cpu
getLimitsCPUContainers[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.resources.limits, "cpu")
	container := allContainers.name
}

# getNoLimitsCPUContainers returns all containers which have not set
# resources.limits.cpu
getNoLimitsCPUContainers[container] {
	container := kubernetes.containers[_].name
	not getLimitsCPUContainers[container]
}

# failLimitsCPU is true if containers[].resources.limits.cpu is not set
# for ANY container
failLimitsCPU {
	count(getNoLimitsCPUContainers) > 0
}

deny[res] {
	failLimitsCPU

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.limits.cpu'", [getNoLimitsCPUContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
        "startline": 6,
        "endline": 10,
	}
}
`,
	})

	scanner := NewScanner(options.ScannerWithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-KSV-0011",
		Aliases:        []string{"KSV011"},
		ShortCode:      "limit-cpu",
		Summary:        "CPU not limited",
		Explanation:    "Enforcing CPU limits prevents DoS via resource exhaustion.",
		Impact:         "",
		Resolution:     "Set a limit value under 'containers[].resources.limits.cpu'.",
		Provider:       "kubernetes",
		Service:        "general",
		Links:          []string{"https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits"},
		Severity:       "LOW",
		Terraform:      (*scan.EngineMetadata)(nil),
		CloudFormation: (*scan.EngineMetadata)(nil),
		CustomChecks:   scan.CustomChecks{Terraform: (*scan.TerraformCustomCheck)(nil)},
		RegoPackage:    "data.builtin.kubernetes.KSV011",
		Frameworks:     map[framework.Framework][]string{},
	}, results.GetFailed()[0].Rule())

	failure := results.GetFailed()[0]
	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     6,
			Content:    "spec: ",
			IsCause:    true,
			FirstCause: true,
			Annotation: "",
		},
		{
			Number:     7,
			Content:    "  containers: ",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     8,
			Content:    "  - command: [\"sh\", \"-c\", \"echo 'Hello' && sleep 1h\"]",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     9,
			Content:    "    image: busybox",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     10,
			Content:    "    name: hello",
			IsCause:    true,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

func Test_FileScan(t *testing.T) {

	results, err := NewScanner(options.ScannerWithEmbeddedPolicies(true)).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_FileScan_WithSeparator(t *testing.T) {

	results, err := NewScanner(options.ScannerWithEmbeddedPolicies(true)).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(`
---
---
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_FileScanWithPolicyReader(t *testing.T) {

	results, err := NewScanner(options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  msg = "fail"
}
`))).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
}

func Test_FileScanJSON(t *testing.T) {

	results, err := NewScanner(options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  input.kind == "Pod"
  msg = "fail"
}
`))).ScanReader(context.TODO(), "k8s.json", strings.NewReader(`
{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    "name": "mongo",
    "labels": {
      "name": "mongo",
      "role": "mongo"
    }
  },
  "spec": {
    "volumes": [
      {
        "name": "mongo-disk",
        "gcePersistentDisk": {
          "pdName": "mongo-disk",
          "fsType": "ext4"
        }
      }
    ],
    "containers": [
      {
        "name": "mongo",
        "image": "mongo:latest",
        "ports": [
          {
            "name": "mongo",
            "containerPort": 27017
          }
        ],
        "volumeMounts": [
          {
            "name": "mongo-disk",
            "mountPath": "/data/db"
          }
        ]
      }
    ]
  }
}
`))
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
}

func Test_FileScanWithMetadata(t *testing.T) {

	results, err := NewScanner(
		options.ScannerWithDebug(os.Stdout),
		options.ScannerWithTrace(os.Stdout),
		options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  input.kind == "Pod"
  msg := {
          "msg": "fail",
          "startline": 2,
		  "endline": 2,
          "filepath": "chartname/template/serviceAccount.yaml"
        }
}
`))).ScanReader(
		context.TODO(),
		"k8s.yaml",
		strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)

	firstResult := results.GetFailed()[0]
	assert.Equal(t, 2, firstResult.Metadata().Range().GetStartLine())
	assert.Equal(t, 2, firstResult.Metadata().Range().GetEndLine())
	assert.Equal(t, "chartname/template/serviceAccount.yaml", firstResult.Metadata().Range().GetFilename())
}

func Test_FileScanExampleWithResultFunction(t *testing.T) {

	results, err := NewScanner(
		options.ScannerWithDebug(os.Stdout),
		options.ScannerWithTrace(os.Stdout),
		options.ScannerWithPolicyReader(strings.NewReader(`package defsec

import data.lib.kubernetes

default checkCapsDropAll = false

__rego_metadata__ := {
"id": "KSV003",
"avd_id": "AVD-KSV-0003",
"title": "Default capabilities not dropped",
"short_code": "drop-default-capabilities",
"version": "v1.0.0",
"severity": "LOW",
"type": "Kubernetes Security Check",
"description": "The container should drop all default capabilities and add only those that are needed for its execution.",
"recommended_actions": "Add 'ALL' to containers[].securityContext.capabilities.drop.",
"url": "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/",
}

__rego_input__ := {
"combine": false,
"selector": [{"type": "kubernetes"}],
}

# Get all containers which include 'ALL' in security.capabilities.drop
getCapsDropAllContainers[container] {
allContainers := kubernetes.containers[_]
lower(allContainers.securityContext.capabilities.drop[_]) == "all"
container := allContainers.name
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getCapsNoDropAllContainers[container] {
container := kubernetes.containers[_]
not getCapsDropAllContainers[container.name]
}

deny[res] {
output := getCapsNoDropAllContainers[_]

msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should add 'ALL' to 'securityContext.capabilities.drop'", [output.name, kubernetes.kind, kubernetes.name]))

res := result.new(msg, output)
}

`))).ScanReader(
		context.TODO(),
		"k8s.yaml",
		strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
    securityContext:
      capabilities:
        drop:
        - nothing
`))
	require.NoError(t, err)

	require.Greater(t, len(results.GetFailed()), 0)

	firstResult := results.GetFailed()[0]
	assert.Equal(t, 8, firstResult.Metadata().Range().GetStartLine())
	assert.Equal(t, 14, firstResult.Metadata().Range().GetEndLine())
	assert.Equal(t, "k8s.yaml", firstResult.Metadata().Range().GetFilename())
}
