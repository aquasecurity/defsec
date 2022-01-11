
### Ensure that logging of lock waits is enabled.

Lock waits are often an indication of poor performance and often an indicator of a potential denial of service vulnerability, therefore occurrences should be logged for analysis.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Issues leading to denial of service may not be identified.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-LOCK-WAITS
        