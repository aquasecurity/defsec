---
additional_links: []
---

Set the aggregator to cover all regions

```yaml
---
Resources:
  GoodExample:
    Type: AWS::Config::ConfigurationAggregator
    Properties:
      AccountAggregationSources:
        - AllAwsRegions: true
      ConfigurationAggregatorName: "GoodAccountLevelAggregation"
```
