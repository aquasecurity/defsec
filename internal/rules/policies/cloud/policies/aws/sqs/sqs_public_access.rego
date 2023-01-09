# METADATA
# title :"SQS Public Access"
# description: "Ensures that SQS queues are not publicly accessible"
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
#   short_code: sqs-public-access 
#   recommended_action: "Update the SQS queue policy to prevent public access."
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
#            sqs_queue_policy_condition_keys: settings.sqs_queue_policy_condition_keys || this.settings.sqs_queue_policy_condition_keys.default
#        };
#        var allowedConditionKeys = config.sqs_queue_policy_condition_keys.split(',');
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.sqs, function(region, rcb){
#            var listQueues = helpers.addSource(cache, source,
#                ['sqs', 'listQueues', region]);
#
#            if (!listQueues) return rcb();
#
#            if (listQueues.err) {
#                helpers.addResult(results, 3,
#                    `Unable to query for SQS queues: ${helpers.addError(listQueues)}`, region);
#                return rcb();
#            }
#
#            if (!listQueues.data || !listQueues.data.length) {
#                helpers.addResult(results, 0, 'No SQS queues found', region);
#                return rcb();
#            }
#
#            async.each(listQueues.data, function(queue, cb){
#                var queueName = queue.substr(queue.lastIndexOf('/') + 1);
#                var resource = `arn:${awsOrGov}:sqs:${region}:${accountId}:${queueName}`;
#
#                var getQueueAttributes = helpers.addSource(cache, source,
#                    ['sqs', 'getQueueAttributes', region, queue]);
#
#                if (!getQueueAttributes ||
#                    getQueueAttributes.err ||
#                    !getQueueAttributes.data ||
#                    !getQueueAttributes.data.Attributes) {
#                    helpers.addResult(results, 3,
#                        `Unable to query attributes for queue "${queueName}"`,
#                        region, resource);
#
#                    return cb();
#                }
#
#                if (!getQueueAttributes.data.Attributes.Policy) {
#                    helpers.addResult(results, 0,
#                        `SQS queue "${queueName}" does not use a policy`,
#                        region, resource);
#                    return cb();
#                }
#
#                var statements = helpers.normalizePolicyDocument(getQueueAttributes.data.Attributes.Policy);
#
#                var publicStatements = [];
#                for (var statement of statements) {
#                    if (statement.Condition && helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, false, accountId)) continue;
#                    if (statement.Effect &&
#                        statement.Effect === 'Allow' &&
#                        helpers.globalPrincipal(statement.Principal)) {
#                        publicStatements.push(statement);
#                    }
#                }
#
#                if (!publicStatements.length) {
#                    helpers.addResult(results, 0,
#                        `SQS queue "${queueName}" is not publicly accessible`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `SQS queue "${queueName}" is publicly accessible`,
#                        region, resource);
#                }
#                
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }