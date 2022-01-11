
### EKS Clusters should have the public access disabled

EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.

### Default Severity
{{ severity "CRITICAL" }}

### Impact
EKS can be access from the internet

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
        