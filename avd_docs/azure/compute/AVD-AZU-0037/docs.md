
### Ensure that no sensitive credentials are exposed in VM custom_data

When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.

### Impact
Sensitive credentials in custom_data can be leaked

<!-- DO NOT CHANGE -->
{{ remediationActions }}

