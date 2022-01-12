
### Retention policy for flow logs should be enabled and set to greater than 90 days

Flow logs are the source of truth for all network activity in your cloud environment. 
To enable analysis in security event that was detected late, you need to have the logs available. 
			
Setting an retention policy will help ensure as much information is available for review.

### Impact
Not enabling retention or having short expiry on flow logs could lead to compromise being undetected limiting time for analysis

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview
        