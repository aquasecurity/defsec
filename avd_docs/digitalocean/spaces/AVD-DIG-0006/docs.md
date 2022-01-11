
### Spaces bucket or bucket object has public read acl set

Space bucket and bucket object permissions should be set to deny public access unless explicitly required.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
The contents of the space can be accessed publicly

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.digitalocean.com/reference/api/spaces-api/#access-control-lists-acls
        