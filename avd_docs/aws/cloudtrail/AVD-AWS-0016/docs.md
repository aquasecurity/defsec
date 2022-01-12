
### Cloudtrail log validation should be enabled to prevent tampering of log data

Log validation should be activated on Cloudtrail logs to prevent the tampering of the underlying data in the S3 bucket. It is feasible that a rogue actor compromising an AWS account might want to modify the log data to remove trace of their actions.

### Impact
Illicit activity could be removed from the logs

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
        