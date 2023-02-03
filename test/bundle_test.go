package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/liamg/memoryfs"

	"github.com/stretchr/testify/require"
)

type manifest struct {
	Revision string   `json:"revision"`
	Roots    []string `json:"roots"`
}

func Test_ManifestValidity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on windows as it doesn't build a bundle on Windows anyway")
	}

	_ = os.RemoveAll("../bundle")
	_ = os.Remove("../bundle.tar.gz")
	defer func() {
		_ = os.RemoveAll("../bundle")
		_ = os.Remove("../bundle.tar.gz")
	}()

	f, err := os.Open("../rules/policies/.manifest")
	require.NoError(t, err)

	var m manifest
	require.NoError(t, json.NewDecoder(f).Decode(&m))

	require.Equal(t, "[GITHUB_SHA]", m.Revision)
	require.Len(t, m.Roots, 1)
	require.Equal(t, "", m.Roots[0])

	cmd := exec.Command("scripts/bundle.sh")
	cmd.Env = append(os.Environ(), "GITHUB_REF=refs/tags/v1.2.3")
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())

	archive, err := os.Open("../bundle.tar.gz")
	require.NoError(t, err)

	gz, err := gzip.NewReader(archive)
	require.NoError(t, err)

	tarReader := tar.NewReader(gz)

	mfs := memoryfs.New()

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)

		switch header.Typeflag {
		case tar.TypeDir:
			require.NoError(t, mfs.MkdirAll(header.Name, 0755))
		case tar.TypeReg:
			buffer := bytes.NewBuffer([]byte{})
			_, err = io.CopyN(buffer, tarReader, header.Size)
			require.NoError(t, err)
			require.NoError(t, mfs.WriteFile(header.Name, buffer.Bytes(), 0644))
		default:
			t.Fatalf("unknown type in %s: 0x%X", header.Name, header.Typeflag)
		}
	}

	mf, err := mfs.Open(".manifest")
	require.NoError(t, err)

	var m2 manifest
	require.NoError(t, json.NewDecoder(mf).Decode(&m2))
	assert.Equal(t, "1.2.3", m2.Revision)
	assert.Len(t, m2.Roots, 1)
	assert.Equal(t, "", m2.Roots[0])

	policies, err := mfs.ReadDir("./policies")
	require.NoError(t, err)

	entries, err := os.ReadDir("../policies")
	require.NoError(t, err)

	var expectedDirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			expectedDirs = append(expectedDirs, entry.Name())
		}
	}

	for _, expected := range expectedDirs {
		var found bool
		for _, policyDir := range policies {
			if policyDir.Name() == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "expected to find policy dir for %s", expected)
	}

}
