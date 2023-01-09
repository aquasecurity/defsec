# METADATA
# title :"CloudFront Distribution Field-Level Encryption"
# description: "Ensure that field-level encryption is enabled for your Amazon CloudFront web distributions."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: cloudfront-field-level-encryption 
#   recommended_action: "Enable field-level encryption for CloudFront distributions."
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
#                'Unable to list CloudFront distributions: ' + helpers.addError(listDistributions));
#            return callback(null, results, source);
#        }
#
#        if (!listDistributions.data.length) {
#            helpers.addResult(results, 0, 'No CloudFront distributions found');
#            return callback(null, results, source);
#        }
#
#        listDistributions.data.forEach(distribution => {
#            if (distribution.DefaultCacheBehavior &&
#                distribution.DefaultCacheBehavior.FieldLevelEncryptionId) {
#                helpers.addResult(results, 0,
#                    'Distribution has field level encryption enabled', 'global', distribution.ARN);
#            } else {
#                helpers.addResult(results, 2,
#                    'Distribution does not have field level encryption enabled', 'global', distribution.ARN);
#            }
#        });
#
#        return callback(null, results, source);
#    }