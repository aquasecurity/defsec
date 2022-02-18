
For the purposes of security, the contents of the plaintext_value field have been marked as sensitive to Terraform, but this does not hide it from state files. State should be treated as sensitive always.

### Impact
Unencrypted sensitive plaintext value can be easily accessible in code.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_environment_secret
 - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
        