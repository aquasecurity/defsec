package kubernetes

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"

	"sigs.k8s.io/yaml"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/rego"
	"github.com/aquasecurity/defsec/rules"
)

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
	prefix := "[debug:scan] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) ScanFS(ctx context.Context, target fs.FS, dir string) (rules.Results, error) {

	var inputs []rego.Input

	if err := fs.WalkDir(target, dir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		s.debug("Scanning %s...", path)

		f, err := target.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		data, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		var v interface{}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return fmt.Errorf("unmarshal yaml: %w", err)
		}

		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: v,
			Type:     types.SourceKubernetes,
		})
		return nil
	}); err != nil {
		return nil, err
	}

	regoScanner := rego.NewScanner(
		rego.OptionWithDebug(s.debugWriter),
		rego.OptionWithPolicyNamespaces(true, s.policyNamespaces...),
	)
	if err := regoScanner.LoadPolicies(len(s.policyDirs) == 0, s.policyDirs...); err != nil {
		return nil, err
	}

	return regoScanner.ScanInput(ctx, inputs...)
}
