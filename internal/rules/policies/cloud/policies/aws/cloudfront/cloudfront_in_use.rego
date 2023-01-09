# METADATA
# title :"CloudFront Enabled"
# description: "Ensure that AWS CloudFront service is used within your AWS account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: cloudfront-in-use 
#   recommended_action: "Create CloudFront distributions as per requirement."
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
#                'Unable to list CloudFront distributions: ' + helpers.addError(listDistributions));
#            return callback(null, results, source);
#        }
#
#        if (listDistributions.data.length) {
#            helpers.addResult(results, 0, 
#                'CloudFront service is in use', 
#                'global');
#        } else {
#            helpers.addResult(results, 2,
#                'CloudFront service is not in use', 
#                'global');
#        }
#
#        return callback(null, results, source);
#    }