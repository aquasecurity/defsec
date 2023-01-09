# METADATA
# title :"CloudTrail Encryption"
# description: "Ensures CloudTrail encryption at rest is enabled for logs"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CloudTrail
#   severity: LOW
#   short_code: cloudtrail-encryption 
#   recommended_action: "Enable CloudTrail log encryption through the CloudTrail console or API"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.cloudtrail, function(region, rcb){
#            var describeTrails = helpers.addSource(cache, source,
#                ['cloudtrail', 'describeTrails', region]);
#
#            if (!describeTrails) return rcb();
#
#            if (describeTrails.err || !describeTrails.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for CloudTrail encryption status: ' + helpers.addError(describeTrails), region);
#                return rcb();
#            }
#
#            if (!describeTrails.data.length) {
#                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
#            } else if (describeTrails.data[0]) {
#                for (var t in describeTrails.data) {
#                    if (describeTrails.data[t].S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) continue;
#                    if (!describeTrails.data[t].KmsKeyId) {
#                        helpers.addResult(results, 2, 'CloudTrail encryption is not enabled',
#                            region, describeTrails.data[t].TrailARN);
#                    } else {
#                        helpers.addResult(results, 0, 'CloudTrail encryption is enabled',
#                            region, describeTrails.data[t].TrailARN);
#                    }
#                }
#            } else {
#                helpers.addResult(results, 2, 'CloudTrail is enabled but is not properly configured', region);
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }