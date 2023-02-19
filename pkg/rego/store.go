package rego

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/storage"
)

// initialise a store populated with OPA data files found in dataPaths
func initStore(dataPaths, namespaces []string, data map[string]interface{}) (storage.Store, error) {
	// FilteredPaths will recursively find all file paths that contain a valid document
	// extension from the given list of data paths.
	allDocumentPaths, err := loader.FilteredPaths(dataPaths, func(abspath string, info os.FileInfo, depth int) bool {
		if info.IsDir() {
			return false
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		for _, filter := range []string{
			".yaml",
			".yml",
			".json",
		} {
			if filter == ext {
				return false
			}
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("filter data paths: %w", err)
	}

	documents, err := loader.NewFileLoader().All(allDocumentPaths)
	if err != nil {
		return nil, fmt.Errorf("load documents: %w", err)
	}

	// pass all namespaces so that rego rule can refer to namespaces as data.namespaces
	documents.Documents["namespaces"] = namespaces

	// Merge passed data into loaded data
	for k, v := range data {
		documents.Documents[k] = v
	}

	store, err := documents.Store()
	if err != nil {
		return nil, fmt.Errorf("get documents store: %w", err)
	}
	return store, nil
}
