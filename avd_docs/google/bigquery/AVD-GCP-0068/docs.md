
BigQuery tables are encrypted by default using Google managed encryption keys. To increase control of the encryption and enable managing factors like key rotation, use a customer-managed key. This alert can often be ignored if the dataset is configured with a default customer-managed encryption key prior to the table creation.

### Impact
Using unmanaged keys does not allow for proper key management.

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://cloud.google.com/bigquery/docs/customer-managed-encryption


