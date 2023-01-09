# METADATA
# title :"CloudFront HTTPS Only"
# description: "Ensures CloudFront distributions are configured to redirect non-HTTPS traffic to HTTPS."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CloudFront.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: cloudfront-https-only 
#   recommended_action: "Remove HTTP-only listeners from distributions."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
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
#
#            if (Distribution.DefaultCacheBehavior.ViewerProtocolPolicy == 'redirect-to-https') {
#                helpers.addResult(results, 0, 'CloudFront distribution ' + 
#                    'is configured to redirect non-HTTPS traffic to HTTPS', 'global', Distribution.ARN);
#            } else if (Distribution.DefaultCacheBehavior.ViewerProtocolPolicy == 'https-only') {
#                helpers.addResult(results, 0, 'The CloudFront ' + 
#                    'distribution is set to use HTTPS only.', 'global', Distribution.ARN);
#            } else {
#                helpers.addResult(results, 2, 'CloudFront distribution ' + 
#                    'is not configured to use HTTPS', 'global', Distribution.ARN);
#            }
#        });
#
#        callback(null, results, source);
#    }