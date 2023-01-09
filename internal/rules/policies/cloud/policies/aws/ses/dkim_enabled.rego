# METADATA
# title :"Email DKIM Enabled"
# description: "Ensures DomainKeys Identified Mail (DKIM) is enabled for domains and addresses in SES."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:SES
#   severity: LOW
#   short_code: dkim-enabled 
#   recommended_action: "Enable DKIM for all domains and addresses in all regions used to send email through SES."
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
#        var accountId = helpers.addSource(cache, source,
#            ['sts', 'getCallerIdentity', acctRegion, 'data']);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.ses, function(region, rcb){
#            var listIdentities = helpers.addSource(cache, source,
#                ['ses', 'listIdentities', region]);
#
#            if (!listIdentities) return rcb();
#
#            if (listIdentities.err || !listIdentities.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for SES identities: ' + helpers.addError(listIdentities), region);
#                return rcb();
#            }
#
#            if (!listIdentities.data.length) {
#                helpers.addResult(results, 0, 'No SES identities found', region);
#                return rcb();
#            }
#
#            var getIdentityDkimAttributes = helpers.addSource(cache, source,
#                ['ses', 'getIdentityDkimAttributes', region]);
#
#            if (!getIdentityDkimAttributes ||
#                getIdentityDkimAttributes.err ||
#                !getIdentityDkimAttributes.data) {
#                helpers.addResult(results, 3,
#                    'Unable to get SES DKIM attributes: ' + helpers.addError(getIdentityDkimAttributes), region);
#                return rcb();
#            }
#
#            for (var i in getIdentityDkimAttributes.data.DkimAttributes) {
#                var resource = `arn:${awsOrGov}:ses:${region}:${accountId}:identity/${i}`;
#                var identity = getIdentityDkimAttributes.data.DkimAttributes[i];
#
#                if (!identity.DkimEnabled) {
#                    helpers.addResult(results, 2, 'DKIM is not enabled', region, resource);
#                } else if (identity.DkimVerificationStatus !== 'Success') {
#                    helpers.addResult(results, 1,
#                        'DKIM is enabled, but not configured properly', region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'DKIM is enabled and configured properly', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }