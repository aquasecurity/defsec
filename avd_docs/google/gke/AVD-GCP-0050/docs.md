
You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.

### Impact
Service accounts with wide permissions can increase the risk of compromise

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa


