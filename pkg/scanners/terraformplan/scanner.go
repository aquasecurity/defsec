package terraformplan

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aquasecurity/defsec/internal/debug"
	"github.com/aquasecurity/defsec/pkg/scan"
	terraformScanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan/parser"
)

type Scanner struct {
	parser    parser.Parser
	parserOpt []parser.Option
	debug     debug.Logger
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

func (s *Scanner) SetDebugWriter(writer io.Writer) {
	s.debug = debug.New(writer, "scan:terraform-plan")
}

func (s *Scanner) ScanFile(filepath string) (scan.Results, error) {

	s.debug.Log("Scanning file %s", filepath)
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

	content, err := planFS.ReadFile("main.tf")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Content: %s\n", string(content))

	scanner := terraformScanner.New(terraformScanner.ScannerWithStopOnHCLError(true))
	return scanner.ScanFS(context.TODO(), planFS, ".")
}
