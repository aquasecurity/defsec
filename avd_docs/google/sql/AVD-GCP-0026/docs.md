
### Disable local_infile setting in MySQL

Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.

### Default Severity
{{ severity "HIGH" }}

### Impact
Arbitrary files read by attackers when combined with a SQL injection vulnerability.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html
        