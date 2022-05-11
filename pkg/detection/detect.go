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
	FileTypeTerraformPlan  FileType = "terraformplan"
	FileTypeDockerfile     FileType = "dockerfile"
	FileTypeKubernetes     FileType = "kubernetes"
	FileTypeYAML           FileType = "yaml"
	FileTypeTOML           FileType = "toml"
	FileTypeJSON           FileType = "json"
	FileTypeHelm           FileType = "helm"
)

var matchers = map[FileType]func(name string, r io.ReadSeeker) bool{}

// nolint
func init() {

	matchers[FileTypeJSON] = func(name string, r io.ReadSeeker) bool {
		ext := filepath.Ext(filepath.Base(name))
		if !strings.EqualFold(ext, ".json") {
			return false
		}
		if resetReader(r) == nil {
			return true
		}

		var content interface{}
		return json.NewDecoder(r).Decode(&content) == nil
	}

	matchers[FileTypeYAML] = func(name string, r io.ReadSeeker) bool {
		ext := filepath.Ext(filepath.Base(name))
		if !strings.EqualFold(ext, ".yaml") && !strings.EqualFold(ext, ".yml") {
			return false
		}
		if resetReader(r) == nil {
			return true
		}

		var content interface{}
		return yaml.NewDecoder(r).Decode(&content) == nil
	}

	matchers[FileTypeHelm] = func(name string, r io.ReadSeeker) bool {
		if IsHelmChartArchive(name, r) {
			return true
		}

		return strings.HasSuffix(name, "hart.yaml")
	}

	matchers[FileTypeTOML] = func(name string, r io.ReadSeeker) bool {
		ext := filepath.Ext(filepath.Base(name))
		return strings.EqualFold(ext, ".toml")
	}

	matchers[FileTypeTerraform] = func(name string, _ io.ReadSeeker) bool {
		ext := filepath.Ext(filepath.Base(name))
		return strings.EqualFold(ext, ".tf") || strings.EqualFold(ext, ".tf.json")
	}

	matchers[FileTypeTerraformPlan] = func(name string, r io.ReadSeeker) bool {
		if IsType(name, r, FileTypeJSON) {
			if resetReader(r) == nil {
				return false
			}

			data, err := ioutil.ReadAll(r)
			if err != nil {
				return false
			}

			contents := make(map[string]interface{})
			err = json.Unmarshal(data, &contents)
			if err == nil {
				if _, ok := contents["terraform_version"]; ok {
					_, stillOk := contents["format_version"]
					return stillOk
				}
			}
		}
		return false
	}

	matchers[FileTypeCloudFormation] = func(name string, r io.ReadSeeker) bool {
		var unmarshalFunc func([]byte, interface{}) error

		switch {
		case IsType(name, r, FileTypeYAML):
			unmarshalFunc = yaml.Unmarshal
		case IsType(name, r, FileTypeJSON):
			unmarshalFunc = json.Unmarshal
		default:
			return false
		}

		if resetReader(r) == nil {
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

	matchers[FileTypeDockerfile] = func(name string, _ io.ReadSeeker) bool {
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

	matchers[FileTypeHelm] = func(name string, r io.ReadSeeker) bool {
		helmFiles := []string{"Chart.yaml", ".helmignore", "values.schema.json", "NOTES.txt"}
		for _, expected := range helmFiles {
			if strings.HasSuffix(name, expected) {
				return true
			}
		}
		helmFileExtensions := []string{".yaml", ".tpl"}
		ext := filepath.Ext(filepath.Base(name))
		for _, expected := range helmFileExtensions {
			if strings.EqualFold(ext, expected) {
				return true
			}
		}
		return IsHelmChartArchive(name, r)
	}

	matchers[FileTypeKubernetes] = func(name string, r io.ReadSeeker) bool {

		if !IsType(name, r, FileTypeYAML) && !IsType(name, r, FileTypeJSON) {
			return false
		}
		if resetReader(r) == nil {
			return false
		}

		contents, err := ioutil.ReadAll(r)
		if err != nil {
			return false
		}

		expectedProperties := []string{"apiVersion", "kind", "metadata", "spec"}

		if IsType(name, r, FileTypeJSON) {
			var result map[string]interface{}
			if err := json.Unmarshal(contents, &result); err != nil {
				return false
			}
			for _, expected := range expectedProperties {
				if _, ok := result[expected]; !ok {
					return false
				}
			}
			return true
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
			for _, expected := range expectedProperties {
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

func IsType(name string, r io.ReadSeeker, t FileType) bool {
	r = ensureSeeker(r)
	f, ok := matchers[t]
	if !ok {
		return false
	}
	return f(name, r)
}

func GetTypes(name string, r io.ReadSeeker) []FileType {
	var matched []FileType
	r = ensureSeeker(r)
	for check, f := range matchers {
		if f(name, r) {
			matched = append(matched, check)
		}
		resetReader(r)
	}
	return matched
}

func ensureSeeker(r io.Reader) io.ReadSeeker {
	if r == nil {
		return nil
	}
	if seeker, ok := r.(io.ReadSeeker); ok {
		return seeker
	}
	if data, err := ioutil.ReadAll(r); err == nil {
		return bytes.NewReader(data)
	}
	return nil
}

func resetReader(r io.Reader) io.ReadSeeker {
	if r == nil {
		return nil
	}
	if seeker, ok := r.(io.ReadSeeker); ok {
		_, _ = seeker.Seek(0, 0)
		return seeker
	}
	return ensureSeeker(r)
}
