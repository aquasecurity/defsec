# METADATA
# title :"AMI Has Tags"
# description: "Ensure that AMIs have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/about-aws/whats-new/2020/12/amazon-machine-images-support-tag-on-create-tag-based-access-control/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ami-has-tags 
#   recommended_action: "Modify AMI and add tags."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
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
#            for (var ami of describeImages.data) {
#                if (!ami.ImageId) continue;
#                
#                const arn ='arn:' + awsOrGov + ':ec2:' + region + '::image/' + ami.ImageId;
#                if (!ami.Tags || !ami.Tags.length) {
#                    helpers.addResult(results, 2, 'AMI does not have any tags', region, arn);
#                } else {
#                    helpers.addResult(results, 0, 'AMI has tags', region, arn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }