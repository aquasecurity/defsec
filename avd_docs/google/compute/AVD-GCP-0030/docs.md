
### Disable project-wide SSH keys for all instances

Use of project-wide SSH keys means that a compromise of any one of these key pairs can result in all instances being compromised. It is recommended to use instance-level keys.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Compromise of a single key pair compromises all instances

<!-- DO NOT CHANGE -->
{{ remediationActions }}

