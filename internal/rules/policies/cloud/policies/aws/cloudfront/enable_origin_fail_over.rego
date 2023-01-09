# METADATA
# title :"CloudFront Enable Origin Failover"
# description: "Ensure that Origin Failover feature is enabled for your CloudFront distributions in order to improve the availability of the content delivered to your end users."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_OriginGroupFailoverCriteria.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: enable-origin-fail-over 
#   recommended_action: "Modify CloudFront distributions and configure origin group instead of a single origin"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#
#        var results = [];
#        var source = {};
#        var region = helpers.defaultRegion(settings);
#
#        var listDistributions = helpers.addSource(cache, source,
#            ['cloudfront', 'listDistributions', region]);
#
#        if (!listDistributions) return callback(null, results, source);
#
#        if (listDistributions.err || !listDistributions.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions), 'global');
#            return callback(null, results, source);
#        }
#
#        if (!listDistributions.data.length) {
#            helpers.addResult(results, 0, 'No CloudFront distributions found', 'global');
#            return callback(null, results, source);
#        }
#
#        // loop through Instances for every reservation
#        listDistributions.data.forEach(distribution => {
#            if (distribution.OriginGroups && distribution.OriginGroups.Quantity) {
#                helpers.addResult(results, 0,
#                    'CloudFront distribution have origin failover enabled.', 'global', distribution.ARN);
#            } else {
#                helpers.addResult(results, 2,
#                    'CloudFront distribution does not have origin failover enabled.', 'global', distribution.ARN);
#            }
#        });
#
#        return callback(null, results, source);
#    }