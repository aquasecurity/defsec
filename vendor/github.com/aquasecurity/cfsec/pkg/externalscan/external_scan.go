package externalscan

import (
	"fmt"
	"os"

	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/cfsec/internal/app/cfsec/debug"
	_ "github.com/aquasecurity/cfsec/internal/app/cfsec/loader"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
)

type ExternalScanner struct {
	internalOptions []scanner.Option
	debugEnabled    bool
}

func NewExternalScanner(options ...Option) *ExternalScanner {
	external := &ExternalScanner{}
	for _, option := range options {
		option(external)
	}
	return external
}

func (t *ExternalScanner) Scan(toScan string) ([]rules.FlatResult, error) {
	defer func() {
		if r := recover(); r != nil {
			debug.Log("error: %v", r)
			fmt.Printf("an error was encountered scanning %s\n", toScan)
		}
	}()
	fileContexts, err := parser.NewParser().ParseFiles(toScan)
	if err != nil {
		switch err.(type) {
		case *parser.ErrParsingErrors:
			fmt.Fprintf(os.Stderr, "There were issues with parsing some files. %v", err)
		default:
			_, _ = fmt.Fprintf(os.Stderr, "An unrecoverable error occurred during parsing. %v", err)
			os.Exit(1)
		}
	}

	var results []rules.FlatResult
	internal := scanner.New(t.internalOptions...)

	for _, res := range internal.Scan(fileContexts) {
		results = append(results, res.Flatten())
	}

	return results, nil
}
