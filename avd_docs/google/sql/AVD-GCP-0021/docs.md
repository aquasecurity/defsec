
### Ensure that logging of long statements is disabled.

Logging of statements which could contain sensitive data is not advised, therefore this setting should preclude all statements from being logged.

### Default Severity
{{ severity "LOW" }}

### Impact
Sensitive data could be exposed in the database logs.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT
        