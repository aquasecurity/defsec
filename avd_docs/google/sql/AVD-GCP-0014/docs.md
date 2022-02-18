
Temporary files are not logged by default. To log all temporary files, a value of `0` should set in the `log_temp_files` flag - as all files greater in size than the number of bytes set in this flag will be logged.

### Impact
Use of temporary files will not be logged

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://postgresqlco.nf/doc/en/param/log_temp_files/
        