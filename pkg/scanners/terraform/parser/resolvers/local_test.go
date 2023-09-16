package resolvers

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/stretchr/testify/assert"
)

func Test_ResolveRecursiveSource(t *testing.T) {

	tests := []struct {
		name string
		dir  string
		opt  Options
	}{
		{
			name: "child module",
			dir:  "testdata/recursive/child_module",
			opt: Options{
				Source:         "../foo",
				OriginalSource: "../foo",
				WorkingDir:     "foo",
				Name:           "module.foo",
				ModulePath:     "foo",
				DebugLogger:    debug.Logger{},
			},
		},
		{
			name: "dot source",
			dir:  "testdata/recursive/dot_source",
			opt: Options{
				Source:         "./.",
				OriginalSource: "./.",
				WorkingDir:     ".",
				Name:           "module.foo",
				ModulePath:     ".",
				DebugLogger:    debug.Logger{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := Local.Resolve(context.TODO(), os.DirFS(tt.dir), tt.opt)
			assert.ErrorContains(t, err, "cannot use itself as a child")
		})
	}
}
