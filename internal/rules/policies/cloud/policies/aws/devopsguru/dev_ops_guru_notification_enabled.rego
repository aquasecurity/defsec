# METADATA
# title :"DevOps Guru Notifications Enabled"
# description: "Ensures SNS topic is set up for Amazon DevOps Guru."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/devops-guru/latest/userguide/setting-up.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DevOpsGuru
#   severity: LOW
#   short_code: dev-ops-guru-notification-enabled 
#   recommended_action: "Add a notification channel to DevOps Guru"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.devopsguru, function(region, rcb){
#            var listNotificationChannels = helpers.addSource(cache, source,
#                ['devopsguru', 'listNotificationChannels', region]);
#
#            if (!listNotificationChannels) return rcb();
#
#            if (listNotificationChannels.err || !listNotificationChannels.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list notification channels: ${helpers.addError(listNotificationChannels)}`, region);
#                return rcb();
#            }
#
#            if (listNotificationChannels.data.length) {
#                helpers.addResult(results, 0, 'SNS notification is configured for DevOps Guru', region);
#            } else {
#                helpers.addResult(results, 2, 'SNS notification is not configured for DevOps Guru', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }