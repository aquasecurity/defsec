
The SecurityContextDeny admission controller can be used to deny pods which make use of some SecurityContext fields which could allow for privilege escalation in the cluster. This should be used where PodSecurityPolicy is not in place within the cluster.

### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://www.cisecurity.org/benchmark/kubernetes


