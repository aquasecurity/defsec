# METADATA
# title :"Public S3 CloudFront Origin"
# description: "Detects the use of an S3 bucket as a CloudFront origin without an origin access identity"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: public-s3-origin 
#   recommended_action: "Create an origin access identity for CloudFront, then make the contents of the S3 bucket private."
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
#        }
#
#        async.each(listDistributions.data, function(distribution, cb){
#            if (!distribution.Origins ||
#                !distribution.Origins.Items ||
#                !distribution.Origins.Items.length) {
#                helpers.addResult(results, 0, 'No CloudFront origins found',
#                    'global', distribution.ARN);
#                return cb();
#            }
#
#            for (var o in distribution.Origins.Items) {
#                var origin = distribution.Origins.Items[o];
#
#                if (origin.S3OriginConfig &&
#                    (!origin.S3OriginConfig.OriginAccessIdentity ||
#                     !origin.S3OriginConfig.OriginAccessIdentity.length)) {
#                    helpers.addResult(results, 2, 'CloudFront distribution is using an S3 ' + 
#                        'origin without an origin access identity', 'global', distribution.ARN);
#                } else {
#                    helpers.addResult(results, 0, 'CloudFront distribution origin is not setup ' +
#                        'without an origin access identity', 'global', distribution.ARN);
#                }
#            }
#
#            cb();
#
#        }, function(){
#            callback(null, results, source);
#        });
#    }