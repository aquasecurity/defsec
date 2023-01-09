# METADATA
# title :"CloudFront Logging Enabled"
# description: "Ensures CloudFront distributions have request logging enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: cloudfront-logging-enabled 
#   recommended_action: "Enable CloudFront request logging."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#
#        var results = [];
#        var source = {};
#
#        var region = helpers.defaultRegion(settings);
#
#        var listDistributions = helpers.addSource(cache, source,
#            ['cloudfront', 'listDistributions', region]);
#
#        if (!listDistributions) return callback(null, results, source);
#
#        if (listDistributions.err || !listDistributions.data) {
#            helpers.addResult(results, 3,
#                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
#            return callback(null, results, source);
#        }
#
#        if (!listDistributions.data.length) {
#            helpers.addResult(results, 0, 'No CloudFront distributions found');
#            return callback(null, results, source);
#        }
#        // loop through Instances for every reservation
#        listDistributions.data.forEach(function(Distribution){
#            var getDistribution = helpers.addSource(cache, source,
#                ['cloudfront', 'getDistribution', region, Distribution.Id]);
#
#            if (!getDistribution || getDistribution.err || !getDistribution.data || !getDistribution.data.Distribution) {
#                helpers.addResult(results, 3,
#                    `Unable to get CloudFront distribution: ${helpers.addError(getDistribution)}`);
#                return;
#            }
#    
#            if (getDistribution.data &&
#                getDistribution.data.Distribution &&
#                getDistribution.data.Distribution.DistributionConfig &&
#                getDistribution.data.Distribution.DistributionConfig.Logging){
#                var logging = getDistribution.data.Distribution.DistributionConfig.Logging;
#                if (logging.Enabled){
#                    helpers.addResult(results, 0,
#                        'Request logging is enabled', 'global', Distribution.ARN);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Request logging is not enabled', 'global', Distribution.ARN);
#                }
#            }
#        });
#
#        return callback(null, results, source);
#    }