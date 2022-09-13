package parser

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/defsec/pkg/detection"
)

func (p *Parser) addTarToFS(path string) (fs.FS, error) {

	var tr *tar.Reader
	var err error

	tarFS := memoryfs.CloneFS(p.workingFS)
	if err != nil {
		return nil, err
	}

	file, err := tarFS.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if detection.IsZip(path) {
		zipped, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer func() { _ = zipped.Close() }()
		tr = tar.NewReader(zipped)
	} else {
		tr = tar.NewReader(file)
	}

	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		// get the individual path and extract to the current directory
		entryPath := header.Name

		switch header.Typeflag {
		case tar.TypeDir:
			if err := tarFS.MkdirAll(entryPath, os.FileMode(header.Mode)); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			writePath := fmt.Sprintf("%s/%s", filepath.Dir(path), entryPath)
			p.debug.Log("Unpacking tar entry %s", writePath)
			_ = tarFS.MkdirAll(filepath.Dir(writePath), fs.ModePerm)
			content := []byte{}
			writer := bytes.NewBuffer(content)

			if err != nil {
				return nil, err
			}
			for {
				_, err := io.CopyN(writer, tr, 1024)
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return nil, err
				}
			}

			p.debug.Log("writing file contents to %s", writePath)
			if err := tarFS.WriteFile(writePath, writer.Bytes(), fs.ModePerm); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("could not untar the section")
		}
	}

	// remove the tarball from the fs
	if err := tarFS.Remove(path); err != nil {
		return nil, err
	}

	return tarFS, nil
}
