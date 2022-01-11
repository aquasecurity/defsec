
### Config configuration aggregator should be using all regions for source

The configuration aggregator should be configured with all_regions for the source. 

This will help limit the risk of any unmonitored configuration in regions that are thought to be unused.

### Default Severity
{{ severity "HIGH" }}

### Impact
Sources that aren't covered by the aggregator are not include in the configuration

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html
        