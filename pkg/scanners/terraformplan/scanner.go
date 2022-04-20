package terraformplan

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aquasecurity/defsec/pkg/scan"
	terraformScanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan/parser"
)

type Scanner struct {
	debugWriter io.Writer
	parser      parser.Parser
	parserOpt   []parser.Option
}

func New(options ...Option) *Scanner {
	scanner := &Scanner{
		parser: *parser.New(),
	}
	for _, o := range options {
		o(scanner)
	}
	return scanner
}

func (s *Scanner) debug(format string, args ...interface{}) {
	if s.debugWriter == nil {
		return
	}
	prefix := "[debug:scan:toml] "
	_, _ = s.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (s *Scanner) ScanFile(filepath string) (scan.Results, error) {

	s.debug("Scanning file %s", filepath)
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	return s.Scan(file)

}

func (s *Scanner) Scan(reader io.Reader) (scan.Results, error) {

	planFile, err := s.parser.Parse(reader)
	if err != nil {
		return nil, err
	}

	planFS, err := planFile.ToFS()
	if err != nil {
		return nil, err
	}

	scanner := terraformScanner.New()
	return scanner.ScanFS(context.TODO(), planFS, ".")
}
