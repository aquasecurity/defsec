
### S3 Access block should block public policy


S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.


### Default Severity
{{ severity "HIGH" }}

### Impact
Users could put a policy that allows public access

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html
        