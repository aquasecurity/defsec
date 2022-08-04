package rbac

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
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - "*"
  resources:
  - secrets
  verbs:
  - list
`,
		"/rules/lib.k8s.rego": `
package lib.kubernetes

default is_gatekeeper = false

is_gatekeeper {
	has_field(input, "review")
	has_field(input.review, "object")
}

object = input {
	not is_gatekeeper
}

object = input.review.object {
	is_gatekeeper
}

format(msg) = gatekeeper_format {
	is_gatekeeper
	gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
	not is_gatekeeper
}

name = object.metadata.name

default namespace = "default"

namespace = object.metadata.namespace

#annotations = object.metadata.annotations

kind = object.kind

is_pod {
	kind = "Pod"
}

is_cronjob {
	kind = "CronJob"
}

default is_controller = false

is_controller {
	kind = "Deployment"
}

is_controller {
	kind = "StatefulSet"
}

is_controller {
	kind = "DaemonSet"
}

is_controller {
	kind = "ReplicaSet"
}

is_controller {
	kind = "ReplicationController"
}

is_controller {
	kind = "Job"
}

split_image(image) = [image, "latest"] {
	not contains(image, ":")
}

split_image(image) = [image_name, tag] {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) = all_containers {
	keys = {"containers", "initContainers"}
	all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers[container] {
	all_containers = pod_containers(object)
	container = all_containers[_]
}

pods[pod] {
	is_pod
	pod = object
}

pods[pod] {
	is_controller
	pod = object.spec.template
}

pods[pod] {
	is_cronjob
	pod = object.spec.jobTemplate.spec.template
}

volumes[volume] {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) {
	container.securityContext.capabilities.add[_] == cap
}

has_field(obj, field) {
	obj[field]
}

no_read_only_filesystem(c) {
	not has_field(c, "securityContext")
}

no_read_only_filesystem(c) {
	has_field(c, "securityContext")
	not has_field(c.securityContext, "readOnlyRootFilesystem")
}

priviledge_escalation_allowed(c) {
	not has_field(c, "securityContext")
}

priviledge_escalation_allowed(c) {
	has_field(c, "securityContext")
	has_field(c.securityContext, "allowPrivilegeEscalation")
}

annotations[annotation] {
	pods[pod]
	annotation = pod.metadata.annotations
}

host_ipcs[host_ipc] {
	pods[pod]
	host_ipc = pod.spec.hostIPC
}

host_networks[host_network] {
	pods[pod]
	host_network = pod.spec.hostNetwork
}

host_pids[host_pid] {
	pods[pod]
	host_pid = pod.spec.hostPID
}

host_aliases[host_alias] {
	pods[pod]
	host_alias = pod.spec
}
`,
		"/rules/lib.util.rego": `
package lib.utils

has_key(x, k) {
	_ = x[k]
}
`,
		"/rules/rule.rego": `
package builtin.kubernetes.KSV041

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV041",
	"avd_id": "AVD-KSV-0041",
	"title": "manage secrets",
	"short_code": "manage-secrets",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit managing secrets",
	"recommended_actions": "create a Role which do not permit to manage secrets if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

resourceManageSecret {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	resourceManageSecret
	msg := "role permit to view specific secret"
	res := {
			"msg": msg,
			"id": __rego_metadata__.id,
			"title": __rego_metadata__.title,
			"severity": __rego_metadata__.severity,
			"type": __rego_metadata__.type,
			"startline": 6,
			"endline": 10,
		}
	}`,
	})

	scanner := NewScanner(options.ScannerWithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	rule := results.GetFailed()[0].Rule()
	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-KSV-0041",
		Aliases:        []string{"KSV041"},
		ShortCode:      "manage-secrets",
		Summary:        "manage secrets",
		Explanation:    "check weather Role permit managing secrets",
		Impact:         "",
		Resolution:     "create a Role which do not permit to manage secrets if not needed",
		Provider:       "rbac",
		Service:        "general",
		Links:          []string{"https://kubernetes.io/docs/concepts/security/rbac-good-practices/"},
		Severity:       "CRITICAL",
		Terraform:      (*scan.EngineMetadata)(nil),
		CloudFormation: (*scan.EngineMetadata)(nil),
		CustomChecks:   scan.CustomChecks{Terraform: (*scan.TerraformCustomCheck)(nil)},
		RegoPackage:    "data.builtin.kubernetes.KSV041",
		Frameworks:     map[framework.Framework][]string{},
	}, rule)

	failure := results.GetFailed()[0]
	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     6,
			Content:    "  name: pod-reader",
			IsCause:    true,
			FirstCause: true,
			Annotation: "",
		},
		{
			Number:     7,
			Content:    "rules:",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     8,
			Content:    "- apiGroups:",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     9,
			Content:    "  - \"*\"",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     10,
			Content:    "  resources:",
			IsCause:    true,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

func Test_FileScan(t *testing.T) {

	results, err := NewScanner(options.ScannerWithEmbeddedPolicies(true)).ScanReader(context.TODO(), "rbac.yaml", strings.NewReader(`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - "*"
  resources:
  - secrets
  verbs:
  - list
`))
	require.NoError(t, err)
	// @todo need to be changed after adding rbac policies
	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_FileScan_WithSeparator(t *testing.T) {

	results, err := NewScanner(options.ScannerWithEmbeddedPolicies(true)).ScanReader(context.TODO(), "rbac.yaml", strings.NewReader(`
---
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - "*"
  resources:
  - secrets
  verbs:
  - list
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_FileScanWithPolicyReader(t *testing.T) {

	results, err := NewScanner(options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  msg = "fail"
}
`))).ScanReader(context.TODO(), "rbac.yaml", strings.NewReader(`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - "*"
  resources:
  - secrets
  verbs:
  - list
`))
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
}

func Test_FileScanJSON(t *testing.T) {

	results, err := NewScanner(options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  input.kind == "Role"
  msg = "fail"
}
`))).ScanReader(context.TODO(), "rbac.json", strings.NewReader(`
{
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "Role",
  "metadata": {
    "namespace": "default",
    "name": "pod-reader"
  },
  "rules": [
    {
      "apiGroups": [
        "*"
      ],
      "resources": [
        "secrets"
      ],
      "verbs": [
        "list"
      ]
    }
  ]
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
  input.kind == "Role"
  msg := {
          "msg": "fail",
          "startline": 2,
		  "endline": 2,
          "filepath": "chartname/template/serviceAccount.yaml"
        }
}
`))).ScanReader(
		context.TODO(),
		"rbac.yaml",
		strings.NewReader(`
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
spec: just
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - "*"
  resources:
  - secrets
  verbs:
  - list
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
		options.ScannerWithPolicyFilesystem(os.DirFS("../../../internal/rules")),
		options.ScannerWithPolicyDirs("defsec/lib", "kubernetes/lib"),
		options.ScannerWithPolicyReader(strings.NewReader(`package defsec

import data.lib.kubernetes
import data.lib.result

__rego_metadata__ := {
	"id": "KSV041",
	"avd_id": "AVD-KSV-0041",
	"title": "manage secrets",
	"short_code": "manage-secrets",
	"severity": "CRITICAL",
	"type": "Kubernetes Security Check",
	"description": "check weather Role permit managing secrets",
	"recommended_actions": "create a Role which do not permit to manage secrets if not needed",
	"url": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "rbac"}],
}

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

resourceManageSecret {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	resourceManageSecret
	msg := "role permit to view specific secret"
	res := result.new(msg, input)
}

`))).ScanReader(
		context.TODO(),
		"rbac.yaml",
		strings.NewReader(`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups:
  - "*"
  resources:
  - secrets
  verbs:
  - list
`))
	require.NoError(t, err)

	require.Greater(t, len(results.GetFailed()), 0)

	firstResult := results.GetFailed()[0]
	assert.Equal(t, 2, firstResult.Metadata().Range().GetStartLine())
	assert.Equal(t, 13, firstResult.Metadata().Range().GetEndLine())
	assert.Equal(t, "rbac.yaml", firstResult.Metadata().Range().GetFilename())
}
