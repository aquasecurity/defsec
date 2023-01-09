# METADATA
# title :"EBS Volumes Too Old Snapshots"
# description: "Ensure that EBS volume snapshots are deleted after defined time period."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.amazonaws.cn/en_us/AWSEC2/latest/UserGuide/ebs-deleting-snapshot.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-old-snapshots 
#   recommended_action: "Delete the EBS snapshots past their defined expiration date"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var config = {
#            ebs_snapshot_life: parseInt(settings.ebs_snapshot_life || this.settings.ebs_snapshot_life.default),
#            ebs_result_limit: parseInt(settings.ebs_result_limit || this.settings.ebs_result_limit.default)
#        };
#
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.ec2, function(region, rcb){
#            var describeSnapshots = helpers.addSource(cache, source,
#                ['ec2', 'describeSnapshots', region]);
#
#            if (!describeSnapshots) return rcb();
#
#            if (describeSnapshots.err || !describeSnapshots.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for EBS Snapshots: ${helpers.addError(describeSnapshots)}`, region);
#                return rcb();
#            }
#
#            if (!describeSnapshots.data.length) {
#                helpers.addResult(results, 0, 'No EBS snapshots present', region);
#                return rcb();
#            }
#
#            var now = new Date();
#            describeSnapshots.data.forEach(snapshot => {
#                if (!snapshot.SnapshotId) return;
#
#                var resource = `arn:${awsOrGov}:${region}:${snapshot.OwnerId}:snapshot/${snapshot.SnapshotId}`;
#                var then = new Date(snapshot.StartTime);
#                var difference = helpers.daysBetween(then, now);
#
#                if (Math.abs(difference) > config.ebs_snapshot_life) {
#                    helpers.addResult(results, 2,
#                        `EBS snapshots is ${config.ebs_snapshot_life} days old`, region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'No old EBS snapshots found', region, resource);
#                }
#            });
#
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }