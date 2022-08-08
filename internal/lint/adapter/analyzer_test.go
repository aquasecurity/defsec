package adapter

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func Test_Analyzer(t *testing.T) {
	_ = analysistest.Run(t, analysistest.TestData(), CreateAnalyzer("provider", "types"), "code", "provider", "types")
}
