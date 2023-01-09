# METADATA
# title :"EBS Volume has tags"
# description: "Ensure that EBS Volumes have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/blogs/aws/new-tag-ec2-instances-ebs-volumes-on-creation/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-volume-has-tags 
#   recommended_action: "Modify EBS volumes and add tags"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.ec2, function(region, rcb) {
#            var describeVolumes = helpers.addSource(cache, source,
#                ['ec2', 'describeVolumes', region]);
#
#            if (!describeVolumes) return rcb();
#
#            if (describeVolumes.err || !describeVolumes.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for EBS Volumes: ' + helpers.addError(describeVolumes), region);
#                return rcb();
#            }
#
#            if (!describeVolumes.data.length) {
#                helpers.addResult(results, 0, 'No EBS Volumes found', region);
#                return rcb();
#            }
#
#            for (let volume of describeVolumes.data) {
#                if (!volume.VolumeId) continue;
#
#                var volumeArn = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':volume/' + volume.VolumeId;
#
#                if (!volume.Tags || !volume.Tags.length) {
#                    helpers.addResult(results, 2, 'EBS volume does not have tags', region, volumeArn);
#                } else {
#                    helpers.addResult(results, 0, 'EBS volume has tags', region, volumeArn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }