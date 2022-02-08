package rego

import (
	"os"
	"path/filepath"
	"strings"
)

func GetAllNonTestRegoFiles() ([]*RegoMetadata, error) {
	var regoFiles []*RegoMetadata

	if err := filepath.Walk("./", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() ||
			strings.HasSuffix(info.Name(), "_test.rego") ||
			!strings.Contains(path, "/policies/") ||
			filepath.Ext(path) != ".rego" {
			return nil
		}

		regoFile, err := NewRegoMetadata(path)
		if err != nil {
			return err
		}
		regoFiles = append(regoFiles, regoFile)

		return nil
	}); err != nil {
		return nil, err
	}

	return regoFiles, nil
}
