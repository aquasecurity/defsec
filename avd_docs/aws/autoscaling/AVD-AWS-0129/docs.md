
Launch template instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.

### Impact
User data is visible through the AWS Management console

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html
        