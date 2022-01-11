package main

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/aquasecurity/defsec/loader"
	"github.com/aquasecurity/defsec/rules"
	"gopkg.in/yaml.v2"
)

func main() {
	if err := filepath.Walk("./avd_docs", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() || !strings.HasPrefix(filepath.Base(path), "AVD") {
			return nil
		}
		return processDir(path)
	}); err != nil {
		panic(err)
	}
}

func processDir(path string) error {
	id := filepath.Base(path)
	for _, rule := range rules.GetRegistered() {
		if rule.Rule().AVDID == id {
			return processRule(path, rule.Rule())
		}
	}
	return fmt.Errorf("check not found for %s", id)
}

func processRule(dir string, rule rules.Rule) error {

	docsMd := fmt.Sprintf(`
### %s

%s

### Default Severity
{{ severity "%s" }}

### Impact
%s

<!-- DO NOT CHANGE -->
{{ remediationActions }}

`,
		rule.Summary,
		rule.Explanation,
		rule.Severity,
		rule.Impact,
	)

	if len(rule.Links) > 0 {
		docsMd += fmt.Sprintf(`### Links
- %s
        `, strings.Join(rule.Links, "\n - "))
	}

	if err := ioutil.WriteFile(filepath.Join(dir, "docs.md"), []byte(docsMd), 0600); err != nil {
		return err
	}

	if err := reformatFile(filepath.Join(dir, "CloudFormation.md")); err != nil {
		return err
	}
	if err := reformatFile(filepath.Join(dir, "Terraform.md")); err != nil {
		return err
	}

	return nil
}

func reformatFile(path string) error {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		if err == os.ErrNotExist {
			return nil
		}
	}

	input := string(data)

	if !strings.HasPrefix(input, "---\n") {
		return nil
	}

	areas := strings.Split(input, "---\n")
	if len(areas) < 3 {
		return fmt.Errorf("invalid frontmatter")
	}

	frontMatter := areas[1]
	rawContent := areas[2]

	matter := struct {
		Links []string `yaml:"additional_links"`
	}{}
	if err := yaml.Unmarshal([]byte(frontMatter), &matter); err != nil {
		return err
	}

	output := cleanCode(string(rawContent))

	if len(matter.Links) > 0 {
		output += fmt.Sprintf(`
#### Remediation Links
 - %s
        `, strings.Join(matter.Links, "\n - "))
	}

	return ioutil.WriteFile(path, []byte(output), 0600)
}

func cleanCode(code string) string {
	var output []string
	var inTF bool
	var indent int
	for _, line := range strings.Split(code, "\n") {
		if inTF {
			if strings.TrimSpace(line) == "```" {
				inTF = false
				indent = 0
			} else {
				// process hcl here
				line = strings.TrimSpace(line)
				line = strings.Repeat("  ", indent) + line
				if strings.HasSuffix(line, "{") {
					indent++
				} else if strings.HasSuffix(line, "}") {
					if !strings.Contains(line, "{") {
						indent--
						line = strings.TrimSpace(line)
						line = strings.Repeat("  ", indent) + line
					}
				}
			}
		} else if strings.TrimSpace(line) == "```hcl" {
			inTF = true
		}
		output = append(output, line)
	}

	return strings.Join(output, "\n")
}
