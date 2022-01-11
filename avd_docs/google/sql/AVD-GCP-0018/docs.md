
### Ensure that Postgres errors are logged

Setting the minimum log severity too high will cause errors not to be logged

### Default Severity
{{ severity "LOW" }}

### Impact
Loss of error logging

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://postgresqlco.nf/doc/en/param/log_min_messages/
 - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES
        