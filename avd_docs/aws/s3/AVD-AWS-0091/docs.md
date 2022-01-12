
### S3 Access Block should Ignore Public Acl


S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.


### Impact
PUT calls with public ACLs specified can make objects public

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
        