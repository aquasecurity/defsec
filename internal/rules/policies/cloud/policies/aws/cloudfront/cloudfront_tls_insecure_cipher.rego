# METADATA
# title :"CloudFront TLS Insecure Cipher"
# description: "Ensures CloudFront distribution TLS Version is not using insecure cipher."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudFront
#   severity: LOW
#   short_code: cloudfront-tls-insecure-cipher 
#   recommended_action: "Modify cloudFront distribution and update the TLS version."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        const deprecatedTLSVersions = [
#            'TLSv1.2_2018',
#            'TLSv1.2_2019',
#        ];
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
# 
#        for (let distribution of listDistributions.data){
#            if (!distribution.ARN) continue;
#            
#            if (distribution.ViewerCertificate && distribution.ViewerCertificate.MinimumProtocolVersion && !deprecatedTLSVersions.includes(distribution.ViewerCertificate.MinimumProtocolVersion)){
#                helpers.addResult(results, 0, 'CloudFront distribution TLS version is secure', 'global', distribution.ARN);
#            } else {
#                helpers.addResult(results, 2, 'CloudFront distribution TLS version is insecure', 'global', distribution.ARN);
#            }
#        }
#        callback(null, results, source);
#    }