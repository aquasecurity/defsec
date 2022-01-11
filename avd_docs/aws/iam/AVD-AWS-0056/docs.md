
### IAM Password policy should prevent password reuse.

IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Password reuse increase the risk of compromised passwords being abused

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details
        