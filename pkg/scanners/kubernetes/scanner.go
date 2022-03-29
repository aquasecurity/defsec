package kubernetes

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes/parser"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/pkg/scanners"
)

var _ scanners.Scanner = (*Scanner)(nil)

type Scanner struct {
	debugWriter      io.Writer
	policyDirs       []string
	dataDirs         []string
	policyNamespaces []string
}

func NewScanner(options ...Option) *Scanner {
	s := &Scanner{
		debugWriter: ioutil.Discard,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan:kubernetes] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (scan.Results, error) {

	k8sFiles, err := parser.New().ParseFS(ctx, target, dir)
	if err != nil {
		return nil, err
	}

	var inputs []rego.Input
	for path, content := range k8sFiles {
		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: content,
			Type:     types.SourceKubernetes,
		})
	}

	regoScanner := rego.NewScanner(
		rego.OptionWithDebug(s.debugWriter),
		rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...),
	)
	if err := regoScanner.LoadPolicies(len(s.policyDirs) == 0, s.policyDirs...); err != nil {
		return nil, err
	}

	s.debug("Scanning %d files...", len(inputs))
	return regoScanner.ScanInput(ctx, inputs...)
}
