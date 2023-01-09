# METADATA
# title :"Shield Emergency Contacts"
# description: "Ensures AWS Shield emergency contacts are configured"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/waf/latest/developerguide/ddos-edit-drt.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Shield
#   severity: LOW
#   short_code: shield-emergency-contacts 
#   recommended_action: "Configure emergency contacts within AWS Shield for the account."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        var describeEmergencyContactSettings = helpers.addSource(cache, source,
#            ['shield', 'describeEmergencyContactSettings', region]);
#
#        if (!describeEmergencyContactSettings) return callback(null, results, source);
#
#        if (describeEmergencyContactSettings.err &&
#            describeEmergencyContactSettings.err.code &&
#            describeEmergencyContactSettings.err.code == 'ResourceNotFoundException') {
#            helpers.addResult(results, 2, 'Shield subscription is not enabled');
#            return callback(null, results, source);
#        }
#
#        if (describeEmergencyContactSettings.err || !describeEmergencyContactSettings.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for Shield emergency contacts: ' + helpers.addError(describeEmergencyContactSettings));
#            return callback(null, results, source);
#        }
#
#        if (!describeEmergencyContactSettings.data.length) {
#            helpers.addResult(results, 2, 'Shield emergency contacts are not configured');
#        } else {
#            helpers.addResult(results, 0, 'Shield emergency contacts are configured with: ' + describeEmergencyContactSettings.data.length + ' contacts');
#        }
#
#        return callback(null, results, source);
#    }