
### Point in time recovery should be enabled to protect DynamoDB table

DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.

### Impact
Accidental or malicious writes and deletes can't be rolled back

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html
        