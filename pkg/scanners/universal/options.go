package universal

import (
	"io"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/dockerfile"
	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform"
)

type Option func(*Scanner)

// OptionWithDebug specifies an io.Writer for debug logs - if not set, they are discarded
func OptionWithDebug(w io.Writer) Option {
	return func(s *Scanner) {
		s.debugWriter = w
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithDebug(w))
		s.cloudformationOpts = append(s.cloudformationOpts, cloudformation.OptionWithDebug(w))
		s.dockerfileOpts = append(s.dockerfileOpts, dockerfile.OptionWithDebug(w))
		s.kubernetesOpts = append(s.kubernetesOpts, kubernetes.OptionWithDebug(w))
	}
}

// OptionWithTrace specifies an io.Writer for trace logs (mainly rego tracing) - if not set, they are discarded
func OptionWithTrace(w io.Writer) Option {
	return func(s *Scanner) {
		s.debugWriter = w
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithTrace(w))
		s.cloudformationOpts = append(s.cloudformationOpts, cloudformation.OptionWithTrace(w))
		s.dockerfileOpts = append(s.dockerfileOpts, dockerfile.OptionWithTrace(w))
		s.kubernetesOpts = append(s.kubernetesOpts, kubernetes.OptionWithTrace(w))
	}
}

// OptionWithTerraformWorkspace specify Terraform workspace
func OptionWithTerraformWorkspace(ws string) Option {
	return func(s *Scanner) {
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithWorkspaceName(ws))
	}
}

// OptionWithTerraformVarsPaths paths to tfvars files for Terraform
func OptionWithTerraformVarsPaths(paths []string) Option {
	return func(s *Scanner) {
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithTFVarsPaths(paths))
	}
}

// OptionWithPolicyDirs - location of rego policy directories - policies are loaded recursively
func OptionWithPolicyDirs(dirs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithPolicyDirs(dirs...))
		s.cloudformationOpts = append(s.cloudformationOpts, cloudformation.OptionWithPolicyDirs(dirs...))
		s.dockerfileOpts = append(s.dockerfileOpts, dockerfile.OptionWithPolicyDirs(dirs...))
		s.kubernetesOpts = append(s.kubernetesOpts, kubernetes.OptionWithPolicyDirs(dirs...))
	}
}

// OptionWithDataDirs - location of rego policy directories - policies are loaded recursively
func OptionWithDataDirs(dirs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithDataDirs(dirs...))
		s.cloudformationOpts = append(s.cloudformationOpts, cloudformation.OptionWithDataDirs(dirs...))
		s.dockerfileOpts = append(s.dockerfileOpts, dockerfile.OptionWithDataDirs(dirs...))
		s.kubernetesOpts = append(s.kubernetesOpts, kubernetes.OptionWithDataDirs(dirs...))
	}
}

// OptionWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func OptionWithPolicyNamespaces(namespaces ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.terraformOpts = append(s.terraformOpts, terraform.OptionWithPolicyNamespaces(namespaces...))
		s.cloudformationOpts = append(s.cloudformationOpts, cloudformation.OptionWithPolicyNamespaces(namespaces...))
		s.dockerfileOpts = append(s.dockerfileOpts, dockerfile.OptionWithPolicyNamespaces(namespaces...))
		s.kubernetesOpts = append(s.kubernetesOpts, kubernetes.OptionWithPolicyNamespaces(namespaces...))
	}
}
