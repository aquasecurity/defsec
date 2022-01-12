
### The default action on Storage account network rules should be set to deny

The default_action for network rules should come into effect when no other rules are matched.

The default action should be set to Deny.

### Impact
Network rules that allow could cause data to be exposed publicly

<!-- DO NOT CHANGE -->
{{ remediationActions }}

### Links
- https://docs.microsoft.com/en-us/azure/firewall/rule-processing
        