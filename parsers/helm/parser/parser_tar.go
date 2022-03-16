package parser

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (p *Parser) addTarball(path string) error {

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	var fr io.ReadCloser = file

	if isZipped(path) {
		if fr, err = gzip.NewReader(file); err != nil {
			return err
		}
	}

	defer func() { fr.Close() }()

	tr := tar.NewReader(fr)
	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		// get the individual path and extract to the current directory
		path := header.Name

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			p.debug("Untarring %s", path)
			_ = os.MkdirAll(filepath.Dir(path), os.ModePerm)
			writer, err := os.Create(path)

			if err != nil {
				return err
			}
			for {
				_, err := io.CopyN(writer, tr, 1024)
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
			}

			if err := os.Chmod(path, os.FileMode(header.Mode)); err != nil {
				return err
			}
			writer.Close()
			if err := p.AddPaths(path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("could not untar the section")
		}
	}

	return nil
}

func isArchive(path string) bool {
	if strings.HasSuffix(path, ".tar") ||
		strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}

func isZipped(path string) bool {
	if strings.HasSuffix(path, ".tgz") ||
		strings.HasSuffix(path, ".tar.gz") {
		return true
	}
	return false
}
