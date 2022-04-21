package detection

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type FileType string

const (
	FileTypeCloudFormation FileType = "cloudformation"
	FileTypeTerraform      FileType = "terraform"
	FileTypeDockerfile     FileType = "dockerfile"
	FileTypeKubernetes     FileType = "kubernetes"
	FileTypeYAML           FileType = "yaml"
	FileTypeTOML           FileType = "toml"
	FileTypeJSON           FileType = "json"
)

var matchers = map[FileType]func(name string, r io.Reader) bool{}

// nolint
func init() {

	matchers[FileTypeJSON] = func(name string, r io.Reader) bool {
		ext := filepath.Ext(filepath.Base(name))
		return strings.EqualFold(ext, ".json")
	}

	matchers[FileTypeYAML] = func(name string, r io.Reader) bool {
		ext := filepath.Ext(filepath.Base(name))
		return strings.EqualFold(ext, ".yaml") || strings.EqualFold(ext, ".yml")
	}

	matchers[FileTypeTOML] = func(name string, r io.Reader) bool {
		ext := filepath.Ext(filepath.Base(name))
		return strings.EqualFold(ext, ".toml")
	}

	matchers[FileTypeTerraform] = func(name string, _ io.Reader) bool {
		ext := filepath.Ext(filepath.Base(name))
		return strings.EqualFold(ext, ".tf") || strings.EqualFold(ext, ".tf.json")
	}

	matchers[FileTypeCloudFormation] = func(name string, r io.Reader) bool {
		var unmarshalFunc func([]byte, interface{}) error

		switch {
		case IsType(name, r, FileTypeYAML):
			unmarshalFunc = yaml.Unmarshal
		case IsType(name, r, FileTypeJSON):
			unmarshalFunc = json.Unmarshal
		default:
			return false
		}

		if r == nil {
			return false
		}

		data, err := ioutil.ReadAll(r)
		if err != nil {
			return false
		}

		contents := make(map[string]interface{})
		if err := unmarshalFunc(data, &contents); err != nil {
			return false
		}
		_, ok := contents["Resources"]
		return ok
	}

	matchers[FileTypeDockerfile] = func(name string, _ io.Reader) bool {
		const requiredFile = "Dockerfile"
		base := filepath.Base(name)
		ext := filepath.Ext(base)
		if strings.TrimSuffix(base, ext) == requiredFile {
			return true
		}
		if strings.EqualFold(ext, "."+requiredFile) {
			return true
		}
		return false
	}

	matchers[FileTypeKubernetes] = func(name string, r io.Reader) bool {

		if !IsType(name, r, FileTypeYAML) {
			return false
		}

		if r == nil {
			return false
		}

		contents, err := ioutil.ReadAll(r)
		if err != nil {
			return false
		}

		marker := "\n---\n"
		altMarker := "\r\n---\r\n"
		if bytes.Contains(contents, []byte(altMarker)) {
			marker = altMarker
		}

		for _, partial := range strings.Split(string(contents), marker) {
			var result map[string]interface{}
			if err := yaml.Unmarshal([]byte(partial), &result); err != nil {
				continue
			}
			match := true
			for _, expected := range []string{"apiVersion", "kind", "metadata", "spec"} {
				if _, ok := result[expected]; !ok {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}

		return false
	}
}

func IsType(name string, r io.Reader, t FileType) bool {
	f, ok := matchers[t]
	if !ok {
		return false
	}
	return f(name, r)
}

func GetTypes(name string, r io.Reader) []FileType {
	var matched []FileType
	if _, ok := r.(io.Seeker); !ok && r != nil {
		if data, err := ioutil.ReadAll(r); err == nil {
			r = bytes.NewReader(data)
		}
	}
	for check, f := range matchers {
		if f(name, r) {
			matched = append(matched, check)
		}
		if seeker, ok := r.(io.Seeker); ok {
			_, _ = seeker.Seek(0, 0)
		}
	}
	return matched
}
