# METADATA
# title :"EventBridge Event Rules In Use"
# description: "Ensure that Amazon EventBridge Events service is in use in order to enable you to react selectively and efficiently to system events."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EventBridge
#   severity: LOW
#   short_code: events-in-use 
#   recommended_action: "Create EventBridge event rules to meet regulatory and compliance requirement within your organization."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        var listRules = helpers.addSource(cache, source,
#            ['eventbridge', 'listRules', region]);
#
#        if (!listRules) return callback(null, results, source);
#
#        if (listRules.err || !listRules.data) {
#            helpers.addResult(results, 3,
#                'Unable to list EventBridge event rules: ' + helpers.addError(listRules), region);
#            return callback(null, results, source);
#        }
#
#        if (listRules.data.length) {
#            helpers.addResult(results, 0, 
#                'EventBridge event rules are in use', 
#                region);
#        } else {
#            helpers.addResult(results, 2,
#                'EventBridge event rules are not in use', 
#                region);
#        }
#
#        return callback(null, results, source);
#    }