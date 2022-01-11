
Do not store plaintext values in your code but rather populate the encrypted_value using fields from a resource, data source or variable.

```hcl
resource "github_actions_environment_secret" "good_example" {
  repository       = "my repository name"
  environment       = "my environment"
  secret_name       = "my secret name"
  encrypted_value   = var.some_encrypted_secret_string
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_environment_secret
 - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
        