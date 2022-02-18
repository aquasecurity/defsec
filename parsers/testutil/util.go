package testutil

import (
	"fmt"

	"github.com/aquasecurity/defsec/parsers/testutil/filesystem"
)

type TestFileExt string

const (
	YamlTestFileExt TestFileExt = "yaml"
	JsonTestFileExt TestFileExt = "json"
)

func CreateTestFile(source string, ext TestFileExt) string {
	testFiles, err := filesystem.New()
	if err != nil {
		panic(err)
	}

	testFile := fmt.Sprintf("testfile.%s", ext)
	if err := testFiles.WriteFile(testFile, []byte(source)); err != nil {
		panic(err)
	}

	return testFiles.RealPath(testFile)
}
