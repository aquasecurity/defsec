
If the <code>workload_metadata_config</code> block within <code>node_config</code> is included, the <code>node_metadata</code> attribute should be configured securely.

The attribute should be set to <code>SECURE</code> to use metadata concealment, or <code>GKE_METADATA_SERVER</code> if workload identity is enabled. This ensures that the VM metadata is not unnecessarily exposed to pods.

### Impact
Metadata that isn't concealed potentially risks leakage of sensitive data

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#create-concealed
        