# METADATA
# title :"Enable All Organization Features"
# description: "Ensures all Organization features are enabled"
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
#   short_code: enable-all-features 
#   recommended_action: "Enable all AWS Organizations features."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#        var describeOrganization = helpers.addSource(cache, source, ['organizations', 'describeOrganization', region]);
#
#        if (!describeOrganization) return callback(null, results, source);
#
#        if (!describeOrganization.data || describeOrganization.err) {
#            if (!describeOrganization.err || describeOrganization.err.code !== 'AWSOrganizationsNotInUseException') {
#                helpers.addResult(results, 3, 'Cannot describe the organization', 'global');
#            }
#            return callback(null, results, source);
#        }
#
#        if (describeOrganization.data.FeatureSet !== 'ALL') {
#            helpers.addResult(results, 2, 'Not all Organization features are enabled', 'global', describeOrganization.data.MasterAccountArn);
#        } else {
#            helpers.addResult(results, 0, 'All Organization features are enabled', 'global', describeOrganization.data.MasterAccountArn);
#        }
#
#        callback(null, results, source);
#    }