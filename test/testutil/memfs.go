package testutil

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/pkg/extrafs"
)

var _ extrafs.OSFS = (*memfs)(nil)

type memfs struct {
	files map[string]memfile
}

type memfile struct {
	reader  io.Reader
	content string
	name    string
	dir     bool
}

func (m memfile) Name() string {
	return m.name
}

func (m memfile) Size() int64 {
	return int64(len(m.content))
}

func (m memfile) Mode() fs.FileMode {
	if m.IsDir() {
		return 0o500
	}
	return 0o400
}

func (m memfile) Info() (fs.FileInfo, error) {
	return m, nil
}

func (m memfile) Type() fs.FileMode {
	return m.Mode()
}

func (m memfile) ModTime() time.Time {
	return time.Now()
}

func (m memfile) IsDir() bool {
	return m.dir
}

func (m memfile) Sys() interface{} {
	return nil
}

func NewMemFS(files map[string]string) fs.FS {
	sys := &memfs{
		files: make(map[string]memfile),
	}
	for name, contents := range files {
		sys.files[toSlash(name)] = memfile{
			content: contents,
		}
	}
	return sys
}

func toSlash(name string) string {
	if name == "." {
		return ""
	}
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimSuffix(name, "/")
	name = strings.TrimPrefix(name, "/")
	return "/" + name
}

func (m *memfs) Stat(name string) (fs.FileInfo, error) {
	name = toSlash(name)
	if f, ok := m.files[name]; ok {
		f.name = filepath.Base(name)
		f.reader = strings.NewReader(f.content)
		return &f, nil
	}
	for path := range m.files {
		if strings.HasPrefix(path, name+"/") {
			return &memfile{
				dir:     true,
				name:    filepath.Base(name),
				reader:  nil,
				content: "",
			}, nil
		}
	}
	return nil, fmt.Errorf("file not found")
}

func (m *memfs) ReadDir(name string) ([]fs.DirEntry, error) {
	name = toSlash(name)
	var entries []fs.DirEntry
	dirs := make(map[string]struct{})
	for path := range m.files {
		if strings.HasPrefix(path, name+"/") {
			if after := strings.TrimPrefix(path, name+"/"); strings.Contains(after, "/") {
				dir := after[:strings.Index(after, "/")] // nolint
				dirs[dir] = struct{}{}
			} else {
				entries = append(entries, &memfile{
					dir:  false,
					name: filepath.Base(path),
				})
			}
		}
	}
	for dir := range dirs {
		entries = append(entries, &memfile{
			dir:  true,
			name: dir,
		})
	}
	return entries, nil
}

func (m *memfs) Open(name string) (fs.File, error) {
	s, err := m.Stat(name)
	if err != nil {
		return nil, err
	}
	if s.IsDir() {
		return nil, fmt.Errorf("cannot open dir for reading")
	}
	return s.(fs.File), nil
}

func (f *memfile) Stat() (fs.FileInfo, error) {
	return f, nil
}

func (f *memfile) Read(data []byte) (int, error) {
	return f.reader.Read(data)
}

func (f *memfile) Close() error {
	return nil
}
