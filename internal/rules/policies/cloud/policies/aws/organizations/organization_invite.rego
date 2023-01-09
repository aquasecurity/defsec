# METADATA
# title :"Organization Invite"
# description: "Ensure all Organization invites are accepted"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html?icmpid=docs_orgs_console
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Organizations
#   severity: LOW
#   short_code: organization-invite 
#   recommended_action: "Enable all AWS Organizations features"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#        var listHandshakesForAccount = helpers.addSource(cache, source, ['organizations', 'listHandshakesForAccount', region]);
#
#        if (!listHandshakesForAccount) return callback(null, results, source);
#
#        if (!listHandshakesForAccount.data || listHandshakesForAccount.err) {
#            helpers.addResult(results, 3, 'Cannot list organization handshakes', 'global');
#            return callback(null, results, source);
#        }
#
#        var invalidHandshakes = listHandshakesForAccount.data.filter(handshake => handshake.State === 'OPEN' && handshake.Action === 'INVITE');
#
#        if (!invalidHandshakes.length) {
#            helpers.addResult(results, 0, 'No pending organization invitations', 'global');
#        } else {
#            for (let invalidHandshake of invalidHandshakes) {
#                helpers.addResult(results, 2, 'Unaccepted pending organization invitations', 'global', invalidHandshake.Arn);
#            }
#        }
#
#        callback(null, results, source);
#    }