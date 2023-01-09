# METADATA
# title :"SNS Valid Subscribers"
# description: "Ensure that Amazon SNS subscriptions are valid and there are no unwanted subscribers."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:SNS
#   severity: LOW
#   short_code: sns-valid-subscribers 
#   recommended_action: "Check for unwanted SNS subscriptions periodically"
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
#            sns_unwanted_subscribers: settings.sns_unwanted_subscribers || this.settings.sns_unwanted_subscribers.default
#        };
#
#        config.sns_unwanted_subscribers = config.sns_unwanted_subscribers.replace(/\s+/g, '');
#
#        if (!config.sns_unwanted_subscribers.length) return callback(null, results, source);
#
#        config.sns_unwanted_subscribers = config.sns_unwanted_subscribers.toLowerCase();
#
#        async.each(regions.sns, function(region, rcb){
#            var listSubscriptions = helpers.addSource(cache, source,
#                ['sns', 'listSubscriptions', region]);
#
#            if (!listSubscriptions) return rcb();
#
#            if (listSubscriptions.err) {
#                helpers.addResult(results, 3,
#                    'Unable to query for SNS subscriptions: ' +
#                    helpers.addError(listSubscriptions), region);
#                return rcb();
#            }
#
#            if (!listSubscriptions.data || !listSubscriptions.data.length) {
#                helpers.addResult(
#                    results, 0, 'No SNS subscriptions Found', region);
#                return rcb();
#            }
#
#            for (let subscriber of listSubscriptions.data) {
#                if (!subscriber.SubscriptionArn) continue;
#
#                let resource = subscriber.SubscriptionArn;
#
#                if (subscriber.Endpoint && config.sns_unwanted_subscribers.includes(subscriber.Endpoint.toLowerCase())){
#                    helpers.addResult(results, 2,
#                        'SNS subscription is an unwanted subscription', region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'SNS subscription is a wanted subscription', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }