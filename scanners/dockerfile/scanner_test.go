package dockerfile

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_BasicScan(t *testing.T) {

	src := `FROM ubuntu

USER root
`

	dir, err := ioutil.TempDir(os.TempDir(), "defsec")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	path := filepath.Join(dir, "Dockerfile")
	require.NoError(
		t,
		ioutil.WriteFile(path, []byte(src), 0o600),
	)

	regoSrc := `package appshield.dockerfile.DS006

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
		"filepath": "Dockerfile",
		"startline": 1,
		"endline": 2,
	}
}

`

	regoPath := filepath.Join(dir, "rule.rego")
	require.NoError(
		t,
		ioutil.WriteFile(regoPath, []byte(regoSrc), 0o600),
	)

	scanner := NewScanner(OptionWithPolicyDirs(dir))
	require.NoError(t, scanner.AddPath(path))

	results, err := scanner.Scan(context.TODO())
	require.NoError(t, err)

	require.Len(t, results, 1)

	//t.Error("add more assertions above")

}
