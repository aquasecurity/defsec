# METADATA
# title :"Encrypted AMI"
# description: "Ensures EBS-backed AMIs are configured to use encryption"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: encrypted-ami 
#   recommended_action: "Ensure all AMIs have encrypted EBS volumes."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeImages = helpers.addSource(cache, source,
#                ['ec2', 'describeImages', region]);
#
#            if (!describeImages) return rcb();
#
#            if (describeImages.err || !describeImages.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for AMIs: ' + helpers.addError(describeImages), region);
#                return rcb();
#            }
#
#            if (!describeImages.data.length) {
#                helpers.addResult(results, 0, 'No AMIs found', region);
#                return rcb();
#            }
#
#            var unencryptedAmis = [];
#
#            describeImages.data.forEach(function(image){
#                image.BlockDeviceMappings.forEach(function(volume){
#                    if (volume.Ebs && !volume.Ebs.Encrypted) {
#                        if (unencryptedAmis.indexOf(image.ImageId) == -1) {
#                            unencryptedAmis.push(image.ImageId);
#                        }
#                    }
#                });
#            });
#
#            if (unencryptedAmis.length > 20) {
#                helpers.addResult(results, 2,
#                    'More than 20 unencrypted AMI EBS volumes found', region);
#            } else if (unencryptedAmis.length) {
#                unencryptedAmis.forEach(function(ami){
#                    helpers.addResult(results, 2,
#                        'AMI EBS volume is unencrypted', region, ami);
#                });
#            } else {
#                helpers.addResult(results, 0,
#                    'No AMIs with unencrypted volumes found', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }