# METADATA
# title :"SNS Topic Encrypted"
# description: "Ensures that Amazon SNS topics enforce Server-Side Encryption (SSE)"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:SNS
#   severity: LOW
#   short_code: topic-encrypted 
#   recommended_action: "Enable Server-Side Encryption to protect the content of SNS topic messages."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.sns, function(region, rcb){
#            var listTopics = helpers.addSource(cache, source,
#                ['sns', 'listTopics', region]);
#
#            if (!listTopics) return rcb();
#
#            if (listTopics.err || !listTopics.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for SNS topics: ' + helpers.addError(listTopics), region);
#                return rcb();
#            }
#
#            if (!listTopics.data.length) {
#                helpers.addResult(results, 0, 'No SNS topics found', region);
#                return rcb();
#            }
#
#            async.each(listTopics.data, function(topic, cb){
#                if (!topic.TopicArn) return cb();
#                
#                var resource = topic.TopicArn;
#                var accountId = resource.split(':')[4];
#                var cloudsploitSNS = helpers.CLOUDSPLOIT_EVENTS_SNS + accountId;
#
#                if ( resource.indexOf(cloudsploitSNS) > -1){
#                    helpers.addResult(results, 0,
#                        'This SNS topic is auto-allowed as part of a cross-account notification topic used by the real-time events service',
#                        region, resource);
#                    return cb();
#                }
#                var getTopicAttributes = helpers.addSource(cache, source,
#                    ['sns', 'getTopicAttributes', region, resource]);
#
#                if (!getTopicAttributes || getTopicAttributes.err || !getTopicAttributes.data) {
#                    helpers.addResult(results, 3,
#                        'Unable to query SNS topic attributes: ' + helpers.addError(getTopicAttributes),
#                        region, resource);
#
#                    return cb();
#                }
#
#                if (getTopicAttributes.data.Attributes &&
#                    getTopicAttributes.data.Attributes.KmsMasterKeyId) {
#                    helpers.addResult(results, 0,
#                        'Server-Side Encryption is enabled for SNS topic',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Server-Side Encryption is not enabled for SNS topic',
#                        region, resource);
#                }
#
#                cb();
#
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }