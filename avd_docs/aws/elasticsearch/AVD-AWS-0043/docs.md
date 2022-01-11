
### Elasticsearch domain uses plaintext traffic for node to node communication.

Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.

### Default Severity
{{ severity "HIGH" }}

### Impact
In transit data between nodes could be read if intercepted

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html
        