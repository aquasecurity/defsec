
### EKS Clusters should have cluster control plane logging turned on

By default cluster control plane logging is not turned on. Logging is available for audit, api, authenticator, controllerManager and scheduler. All logging should be turned on for cluster control plane.

### Default Severity
{{ severity "MEDIUM" }}

### Impact
Logging provides valuable information about access and usage

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
        