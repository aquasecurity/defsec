# METADATA
# title :"Public AMI"
# description: "Checks for publicly shared AMIs"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: public-ami 
#   recommended_action: "Convert the public AMI a private image."
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
#            var found = false;
#
#            // Now lookup flow logs and map to images
#            for (var i in describeImages.data) {
#                var image = describeImages.data[i];
#
#                if (image.Public) {
#                    found = true;
#
#                    helpers.addResult(results, 1, 'AMI is public', region,
#                        'arn:aws:ec2:' + region + '::image/' + image.ImageId);
#                }
#            }
#
#            if (!found) {
#                helpers.addResult(results, 0, 'No public AMIs found', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }