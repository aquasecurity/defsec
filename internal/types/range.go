package types

import (
	"fmt"
	"path/filepath"
)

type Range interface {
	GetFilename() string
	GetStartLine() int
	GetEndLine() int
	String() string
	IsMultiLine() bool
}

func NewRange(filename string, startLine int, endLine int, sourcePrefix ...string) baseRange {
	r := baseRange{
		filename:  filename,
		startLine: startLine,
		endLine:   endLine,
	}
	if len(sourcePrefix) > 0 {
		r.sourcePrefix = sourcePrefix[0]
	}
	return r
}

type baseRange struct {
	filename     string
	startLine    int
	endLine      int
	sourcePrefix string
}

func (r baseRange) GetFilename() string {
	if r.sourcePrefix == "" {
		return r.filename
	}
	return filepath.Join(r.sourcePrefix, r.filename)
}

func (r baseRange) GetStartLine() int {
	return r.startLine
}

func (r baseRange) GetEndLine() int {
	return r.endLine
}

func (r baseRange) IsMultiLine() bool {
	return r.startLine < r.endLine
}

func (r baseRange) String() string {
	if r.startLine != r.endLine {
		return fmt.Sprintf("%s:%d-%d", r.GetFilename(), r.startLine, r.endLine)
	}
	return fmt.Sprintf("%s:%d", r.GetFilename(), r.startLine)
}
