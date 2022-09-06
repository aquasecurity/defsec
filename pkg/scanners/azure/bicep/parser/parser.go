package parser

import (
	"fmt"
	"io"

	"github.com/aquasecurity/defsec/pkg/scanners/azure"
)

type Parser struct {
}

func New() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r io.Reader) (*azure.Deployment, error) {
	_ = r
	return nil, fmt.Errorf("not implemented yet")
}
