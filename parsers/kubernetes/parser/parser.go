package parser

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

type Parser struct {
	debugWriter io.Writer
}

// New creates a new Kubernetes parser
func New() *Parser {
	return &Parser{}
}

func (p *Parser) debug(format string, args ...interface{}) {
	if p.debugWriter == nil {
		return
	}
	prefix := "[debug:parse] "
	_, _ = p.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (p *Parser) Parse(path, manifestContent string) (manifest Manifest, err error) {
	p.debug("Parsing file %s", path)
	if err := yaml.Unmarshal([]byte(manifestContent), &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}
