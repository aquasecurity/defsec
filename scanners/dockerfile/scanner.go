package dockerfile

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/dockerfile/parser"
	"github.com/aquasecurity/defsec/rego"
	"github.com/aquasecurity/defsec/rules"
)

type Scanner struct {
	debugWriter      io.Writer
	policyDirs       []string
	dataDirs         []string
	paths            []string
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

	p := parser.New()
	var inputs []rego.Input
	for _, path := range s.paths {
		dfile, err := p.ParseFile(path)
		if err != nil {
			s.debug("invalid dockerfile at '%s', ignoring: %s", path, err)
			continue
		}

		inputs = append(inputs, rego.Input{
			Path:     path,
			Contents: dfile.ToRego(),
			Type:     types.SourceDockerfile,
		})

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
