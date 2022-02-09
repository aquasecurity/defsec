package rego

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type RegoMetadata struct {
	ID                 string   `json:"id"`
	AVDID              string   `json:"avd_id"`
	Title              string   `json:"title"`
	ShortCode          string   `json:"short_code"`
	Version            string   `json:"version"`
	Type               string   `json:"type"`
	Description        string   `json:"description"`
	Url                string   `json:"url"`
	Severity           string   `json:"severity"`
	RecommendedActions string   `json:"recommended_actions"`
	Links              []string `json:"-"`
	Name               string   `json:"-"`
	FileName           string   `json:"-"`
}

func NewRegoMetadata(filename string) (*RegoMetadata, error) {

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	metadataReplacer := strings.NewReplacer("\n", "", "\t", "", `\\"`, `"`, ",\n}", "}")
	metadataRegex := regexp.MustCompile(`(?m)(?s)__rego_metadata__ := (\{.+?\})`)
	metadata := metadataReplacer.Replace(metadataRegex.FindStringSubmatch(string(content))[1])
	var regoMeta RegoMetadata
	if err := json.Unmarshal([]byte(metadata), &regoMeta); err != nil {
		return nil, err
	}

	regoMeta.Name = filepath.Base(filename)
	regoMeta.FileName = filename
	return &regoMeta, nil
}

func (m *RegoMetadata) Validate() (bool, []string) {

	var failureAttributes []string
	valid := true
	if strings.EqualFold(m.AVDID, "") {
		valid = false
		failureAttributes = append(failureAttributes, "AVDID")
	}
	if strings.EqualFold(m.ID, "") {
		valid = false
		failureAttributes = append(failureAttributes, "ID")
	}
	if strings.EqualFold(m.Title, "") {
		valid = false
		failureAttributes = append(failureAttributes, "Title")
	}
	if strings.EqualFold(m.ShortCode, "") {
		valid = false
		failureAttributes = append(failureAttributes, "ShortCode")
	}
	if strings.EqualFold(m.Description, "") {
		valid = false
		failureAttributes = append(failureAttributes, "Description")
	}
	if strings.EqualFold(m.Severity, "") {
		valid = false
		failureAttributes = append(failureAttributes, "Severity")
	}
	if strings.EqualFold(m.RecommendedActions, "") {
		valid = false
		failureAttributes = append(failureAttributes, "RecommendedActions")
	}
	return valid, failureAttributes

}

func (m *RegoMetadata) DocsFolder() string {
	return filepath.Join("avd_docs", filepath.Dir(strings.ReplaceAll(m.FileName, "policies/", "")), m.AVDID)

}

func (m *RegoMetadata) DocsFilePath() string {
	return filepath.Join(m.DocsFolder(), "docs.md")
}

func (m *RegoMetadata) HasDocsMarkdown() bool {

	if _, err := os.Stat(m.DocsFilePath()); err == nil {
		return true
	}

	return false
}
