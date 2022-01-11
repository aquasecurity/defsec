
### S3 Access block should block public ACL


S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.


### Default Severity
{{ severity "HIGH" }}

### Impact
PUT calls with public ACLs specified can make objects public

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
        