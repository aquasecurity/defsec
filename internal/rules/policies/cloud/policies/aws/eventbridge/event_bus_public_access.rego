# METADATA
# title :"Event Bus Public Access"
# description: "Ensure that EventBridge event bus is configured to prevent exposure to public access."
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
#   short_code: event-bus-public-access 
#   recommended_action: "Configure EventBridge event bus policies that allow access to whitelisted/trusted account principals but not public access."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        var config = {
#            event_bus_policy_condition_keys: settings.event_bus_policy_condition_keys || this.settings.event_bus_policy_condition_keys.default
#        };
#        config.event_bus_policy_condition_keys = config.event_bus_policy_condition_keys.replace(/\s/g, '');
#        var allowedConditionKeys = config.event_bus_policy_condition_keys.split(',');
#
#        async.each(regions.eventbridge, function(region, rcb){
#            var listEventBuses = helpers.addSource(cache, source,
#                ['eventbridge', 'listEventBuses', region]);  
#
#            if (!listEventBuses) return rcb();
#
#            if (listEventBuses.err || !listEventBuses.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list event bus: ' + helpers.addError(listEventBuses), region);
#                return rcb();
#            }
#
#            if (!listEventBuses.data.length) {
#                helpers.addResult(results, 0, 'No Event buses found', region);
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
#                if (!statements || !statements.length) {
#                    helpers.addResult(results, 0,
#                        'Event bus policy does not have statements',
#                        region, eventBus.Arn);
#                    return;
#                }
#
#                var publicActions = [];
#
#                for (var statement of statements) {
#                    var effectEval = (statement.Effect && statement.Effect == 'Allow' ? true : false);
#                    var principalEval = helpers.globalPrincipal(statement.Principal);
#                    let scopedCondition;
#                    if (statement.Condition) scopedCondition = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, false, accountId);
#
#                    if (!scopedCondition && principalEval && effectEval) {
#                        if (statement.Action && typeof statement.Action === 'string') {
#                            if (publicActions.indexOf(statement.Action) === -1) {
#                                publicActions.push(statement.Action);
#                            }
#                        } else if (statement.Action && statement.Action.length) {
#                            for (var a in statement.Action) {
#                                if (publicActions.indexOf(statement.Action[a]) === -1) {
#                                    publicActions.push(statement.Action[a]);
#                                }
#                            }
#                        }
#                    }
#                }
#
#                if (publicActions.length) {
#                    helpers.addResult(results, 2,
#                        'Event bus policy is exposed to everyone' ,
#                        region, eventBus.Arn);
#                } else {
#                    helpers.addResult(results, 0,
#                        'Event bus policy is not exposed to everyone',
#                        region, eventBus.Arn);
#                }
#            });
#         
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }