
### Shielded GKE nodes not enabled.

CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.

### Default Severity
{{ severity "HIGH" }}

### Impact
Node identity and integrity can't be verified without shielded GKE nodes

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes
        