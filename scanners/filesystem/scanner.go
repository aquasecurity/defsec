package filesystem

import (
	"fmt"
	"io/fs"

	"github.com/aquasecurity/defsec/rules"
)

type Scanner struct {
}

func New(opts ...Option) *Scanner {
	s := &Scanner{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Scanner) Scan(fs fs.FS) (rules.Results, error) {
	_ = fs
	return nil, fmt.Errorf("not implemented yet")
}
