
In GitHub Actions, one can authenticate to Google Cloud by setting values for workload_identity_provider and service_account and requesting a short-lived OIDC token which is then used to execute commands as that Service Account. If you don't specify a condition in the workload identity provider pool configuration, then any GitHub Action can assume this role and act as that Service Account.

### Impact
Allows an external attacker to authenticate as the attached service account and act with its permissions

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://www.revblock.dev/exploiting-misconfigured-google-cloud-service-accounts-from-github-actions/


