# METADATA
# title :"Event Bus Cross Account Access"
# description: "Ensure that EventBridge event bus is configured to allow access to whitelisted AWS account principals."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.amazonaws.cn/en_us/eventbridge/latest/userguide/eb-event-bus-perms.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EventBridge
#   severity: LOW
#   short_code: event-bus-cross-account-access 
#   recommended_action: "Configure EventBridge event bus policies that allow access to whitelisted/trusted cross-account principals."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config= {
#            eventbridge_whitelisted_aws_account_principals : settings.eventbridge_whitelisted_aws_account_principals || this.settings.eventbridge_whitelisted_aws_account_principals.default,
#            eventbridge_whitelisted_aws_account_principals_regex : settings.eventbridge_whitelisted_aws_account_principals_regex || this.settings.eventbridge_whitelisted_aws_account_principals_regex.default,
#            eventbridge_whitelist_aws_organization_accounts: settings.eventbridge_whitelist_aws_organization_accounts || this.settings.eventbridge_whitelist_aws_organization_accounts.default,
#            eventbridge_policy_condition_keys: settings.eventbridge_policy_condition_keys || this.settings.eventbridge_policy_condition_keys.default,
#        };
#        var allowedConditionKeys = config.eventbridge_policy_condition_keys.split(',');
#        var makeRegexBased = (config.eventbridge_whitelisted_aws_account_principals_regex.length) ? true : false;
#        var whitelistOrganization = (config.eventbridge_whitelist_aws_organization_accounts == 'true'); 
#        config.eventbridge_whitelisted_aws_account_principals_regex = new RegExp(config.eventbridge_whitelisted_aws_account_principals_regex);
#        var results = [];
#        var source = {};
#        
#        var regions = helpers.regions(settings);
#        var defaultRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', regions.default, 'data']);
#
#        let organizationAccounts = [];
#        if (whitelistOrganization) {
#            var listAccounts = helpers.addSource(cache, source,
#                ['organizations', 'listAccounts', defaultRegion]);
#
#            if (!listAccounts || listAccounts.err || !listAccounts.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, defaultRegion);
#                return callback(null, results, source);
#            }
#            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
#        }
#        
#        async.each(regions.eventbridge, function(region, rcb){
#            var listEventBuses = helpers.addSource(cache, source,
#                ['eventbridge', 'listEventBuses', region]);
#            
#            if (!listEventBuses) return rcb();
#
#            if (listEventBuses.err || !listEventBuses.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Event Bus: ${helpers.addError(listEventBuses)}`, region);
#                return rcb();
#            }
#
#            if (!listEventBuses.data.length) {
#                helpers.addResult(results, 0, 'No Event Buses found', region);
#                return rcb();
#            }
#            
#            listEventBuses.data.forEach(eventBus => {
#                if (!eventBus.Arn) return;
#
#                if (!eventBus.Policy) {
#                    helpers.addResult(results, 0, 'Event bus does not use custom policy', region, eventBus.Arn);
#                    return;
#                }
#
#                var statements = helpers.normalizePolicyDocument(eventBus.Policy);
#    
#                if (!statements){
#                    helpers.addResult(results, 0, 'No statement exists for the policy', region, eventBus.Arn);
#                    return;
#                }
#                var restrictedAccountPrincipals = [];
#                var crossAccountEventBus = false;
#    
#                statements.forEach(statement => {
#                    if (!statement.Principal) return;
#
#                    let conditionalPrincipals = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId);
#                    if (helpers.crossAccountPrincipal(statement.Principal, accountId) ||
#                        (conditionalPrincipals && conditionalPrincipals.length)) {
#                        let crossAccountPrincipals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
#
#                        if (conditionalPrincipals && conditionalPrincipals.length) {
#                            conditionalPrincipals.forEach(conPrincipal => {
#                                if (!conPrincipal.includes(accountId)) crossAccountPrincipals.push(conPrincipal);
#                            });
#                        }
#
#                        if (!crossAccountPrincipals.length) return;
#
#                        crossAccountEventBus = true;
#                        crossAccountPrincipals.forEach(principal => {
#                            if (whitelistOrganization) {
#                                if (organizationAccounts.find(account => principal.includes(account))) return;
#                            }
#                            if (makeRegexBased) {
#                                if (!config.eventbridge_whitelisted_aws_account_principals_regex.test(principal) &&
#                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
#                            } else if (!config.eventbridge_whitelisted_aws_account_principals.includes(principal) &&
#                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
#                        });
#                    }
#                });
#
#                if (crossAccountEventBus && !restrictedAccountPrincipals.length) {
#                    helpers.addResult(results, 0,
#                        'Event bus contains trusted account principals only', region, eventBus.Arn);
#                } else if (crossAccountEventBus) {
#                    helpers.addResult(results, 2,
#                        `Event bus contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`,
#                        region, eventBus.Arn);
#                } else {
#                    helpers.addResult(results, 0,
#                        'Event bus does not contain cross-account policy statement', region, eventBus.Arn);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }