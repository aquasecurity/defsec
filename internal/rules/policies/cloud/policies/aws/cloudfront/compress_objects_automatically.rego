# METADATA
# title :"CloudFront Compress Objects Automatically"
# description: "Ensure that your Amazon Cloudfront distributions are configured to automatically compress files(object)."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: compress-objects-automatically 
#   recommended_action: "Ensures that CloudFront is configured to automatically compress files"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
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
#            if (distribution.DefaultCacheBehavior && distribution.DefaultCacheBehavior.Compress) {
#                helpers.addResult(results, 0,
#                    'CloudFront distribution is configured to compress files automatically', 'global', distribution.ARN);
#            } else {
#                helpers.addResult(results, 2,
#                    'CloudFront distribution is not configured to compress files automatically', 'global', distribution.ARN);
#            }
#        });
#
#        return callback(null, results, source);
#    }