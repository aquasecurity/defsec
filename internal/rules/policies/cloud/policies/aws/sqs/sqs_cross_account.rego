# METADATA
# title :"SQS Cross Account Access"
# description: "Ensures SQS policies disallow cross-account access"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:SQS
#   severity: LOW
#   short_code: sqs-cross-account 
#   recommended_action: "Update the SQS policy to prevent access from external accounts."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            sqs_whitelisted_aws_account_principals : settings.sqs_whitelisted_aws_account_principals || this.settings.sqs_whitelisted_aws_account_principals.default,
#            sqs_whitelist_aws_organization_accounts: settings.sqs_whitelist_aws_organization_accounts || this.settings.sqs_whitelist_aws_organization_accounts.default,
#            sqs_queue_policy_condition_keys: settings.sqs_queue_policy_condition_keys || this.settings.sqs_queue_policy_condition_keys.default,
#        };
#
#        var allowedConditionKeys = config.sqs_queue_policy_condition_keys.split(',');
#        var whitelistOrganization = (config.sqs_whitelist_aws_organization_accounts == 'true');
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        let organizationAccounts = [];
#        if (whitelistOrganization) {
#            var listAccounts = helpers.addSource(cache, source,
#                ['organizations', 'listAccounts', acctRegion]);
#    
#            if (!listAccounts || listAccounts.err || !listAccounts.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, acctRegion);
#                return callback(null, results, source);
#            }
#
#            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
#        }
#
#        async.each(regions.sqs, function(region, rcb){
#            var listQueues = helpers.addSource(cache, source,
#                ['sqs', 'listQueues', region]);
#
#            if (!listQueues) return rcb();
#
#            if (listQueues.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for SQS queues: ' + helpers.addError(listQueues), region);
#                return rcb();
#            }
#
#            if (!listQueues.data || !listQueues.data.length) {
#                helpers.addResult(results, 0, 'No SQS queues found', region);
#                return rcb();
#            }
#
#            listQueues.data.forEach(queue => {
#                var getQueueAttributes = helpers.addSource(cache, source,
#                    ['sqs', 'getQueueAttributes', region, queue]);
#
#                if (!getQueueAttributes ||
#                    getQueueAttributes.err ||
#                    !getQueueAttributes.data ||
#                    !getQueueAttributes.data.Attributes ||
#                    !getQueueAttributes.data.Attributes.QueueArn) {
#                    helpers.addResult(results, 3,
#                        'Unable to query SQS for queue: ' + queue,
#                        region);
#                    return;
#                }
#
#                var queueArn = getQueueAttributes.data.Attributes.QueueArn;
#
#                if (!getQueueAttributes.data.Attributes.Policy) {
#                    helpers.addResult(results, 0,
#                        'The SQS queue does not use a custom policy',
#                        region, queueArn);
#                    return;
#                }
#
#                try {
#                    var policy = JSON.parse(getQueueAttributes.data.Attributes.Policy);
#                } catch (e) {
#                    helpers.addResult(results, 3,
#                        'The SQS queue policy could not be parsed to valid JSON.',
#                        region, queueArn);
#
#                    return;
#                }
#
#                var globalActions = [];
#                var crossAccountActions = [];
#
#                var statements = helpers.normalizePolicyDocument(policy);
#
#                for (var statement of statements) {
#                    if (!statement.Effect || statement.Effect !== 'Allow' || !statement.Principal) continue;
#
#                    var crossAccountAccess = false;
#                    var conditionalPrincipals = (statement.Condition) ?
#                        helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId) : [];
#
#                    if (helpers.globalPrincipal(statement.Principal)) {
#                        // if (statement.Condition && helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, false, accountId)) continue;
#                        if (statement.Condition && conditionalPrincipals.length) {
#                            for (let principal of conditionalPrincipals) {
#                                if (helpers.crossAccountPrincipal(principal, accountId)) {
#                                    crossAccountAccess = true;
#                                    break;
#                                }
#                            }
#                        } else {
#                            for (var a in statement.Action) {
#                                if (globalActions.indexOf(statement.Action[a]) === -1) {
#                                    globalActions.push(statement.Action[a]);
#                                }
#                            }
#                        }
#                    }
#
#                    if (helpers.crossAccountPrincipal(statement.Principal, accountId)) crossAccountAccess = true;
#
#                    if (crossAccountAccess) {
#                        if (helpers.crossAccountPrincipal(statement.Principal, accountId) ||
#                            (conditionalPrincipals && conditionalPrincipals.length)) {
#                            let crossAccountPrincipals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
#
#                            if (conditionalPrincipals && conditionalPrincipals.length) {
#                                conditionalPrincipals.forEach(conPrincipal => {
#                                    if (!conPrincipal.includes(accountId)) crossAccountPrincipals.push(conPrincipal);
#                                });
#                            }
#
#                            if (!crossAccountPrincipals.length) continue;
#
#                            let crossAccount = false;
#
#                            for (let principal of crossAccountPrincipals) {
#                                if (config.sqs_whitelisted_aws_account_principals.includes(principal)) continue;
#                                if (whitelistOrganization &&
#                                    organizationAccounts.find(account => principal.includes(account))) continue;
#
#                                crossAccount = true;
#                                break;
#                            }
#
#                            if (crossAccount) {
#                                for (a in statement.Action) {
#                                    if (crossAccountActions.indexOf(statement.Action[a]) === -1) {
#                                        crossAccountActions.push(statement.Action[a]);
#                                    }
#                                }
#                            }
#                        }
#                    }
#                }
#
#                if (globalActions.length) {
#                    helpers.addResult(results, 2,
#                        'The SQS queue policy allows global access to the action(s): ' + globalActions,
#                        region, queueArn);
#                } else if (crossAccountActions.length) {
#                    helpers.addResult(results, 2,
#                        'The SQS queue policy allows cross-account access to the action(s): ' + crossAccountActions,
#                        region, queueArn);
#                } else {
#                    helpers.addResult(results, 0,
#                        'The SQS queue policy does not allow global or cross-account access.',
#                        region, queueArn);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }