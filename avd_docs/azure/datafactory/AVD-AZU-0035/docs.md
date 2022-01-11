
### Data Factory should have public access disabled, the default is enabled.

Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
Data factory is publicly accessible

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios
        