package kubernetes

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/rego"
	"github.com/aquasecurity/defsec/rules"
)

type Scanner struct {
	debugWriter io.Writer
	policyDirs  []string
	dataDirs    []string
	paths       []string
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

func (s *Scanner) AddPath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return fmt.Errorf("path is directory")
	}

	s.paths = append(s.paths, path)
	return nil
}

func (s *Scanner) Scan(ctx context.Context) (rules.Results, error) {

	var inputs []rego.Input
	for _, path := range s.paths {

		s.debug("Scanning %s...", path)

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var v interface{}
		if err := yaml.Unmarshal(data, &v); err != nil {
			return nil, xerrors.Errorf("unmarshal yaml: %w", err)
		}

		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: v,
			Type:     types.SourceKubernetes,
		})

	}

	regoScanner := rego.NewScanner(
		rego.OptionWithDebug(s.debugWriter),
	)
	if err := regoScanner.LoadPolicies(len(s.policyDirs) == 0, s.policyDirs...); err != nil {
		return nil, err
	}

	return regoScanner.ScanInput(ctx, inputs...)
}
