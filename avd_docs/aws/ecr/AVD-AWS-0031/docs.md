
### ECR images tags shouldn't be mutable.

ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>

### Default Severity
{{ severity "HIGH" }}

### Impact
Image tags could be overwritten with compromised images

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://sysdig.com/blog/toctou-tag-mutability/
        