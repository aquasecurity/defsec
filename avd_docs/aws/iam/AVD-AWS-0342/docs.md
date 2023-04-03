

       When a service that needs to perform other actions is used (user, role, human, code, or service), the AWS architecture frequently has that service assume an AWS role to carry out the other actions, the service carrying out the actions is "provided" a role by the calling principal and implicitly takes on that role to carry out the actions (instead of executing sts:AssumeRole).
       The privileges attached to the role are distinct from those of the primary ordering the action and may even be larger and can cause security issues.
           

### Impact
Compromise on security of aws resources.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html


