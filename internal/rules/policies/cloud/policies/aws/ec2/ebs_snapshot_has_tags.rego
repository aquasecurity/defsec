# METADATA
# title :"EBS Snapshot Has Tags"
# description: "Ensure that EBS snapshots have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://aws.amazon.com/blogs/compute/tag-amazon-ebs-snapshots-on-creation-and-implement-stronger-security-policies/
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-snapshot-has-tags 
#   recommended_action: "Modify EBS snapshots and add tags."
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
#                helpers.addResult(results, 0, 'No EBS snapshots found', region);
#                return rcb();
#            }
#            for (let snapshot of describeSnapshots.data){
#                if (!snapshot.OwnerId || !snapshot.SnapshotId) continue;
#
#                var resourceARN = `arn:${awsOrGov}:${region}:${snapshot.OwnerId}:snapshot/${snapshot.SnapshotId}`;
#
#                if (!snapshot.Tags || !snapshot.Tags.length) {
#                    helpers.addResult(results, 2, 'EBS Snapshot does not have tags', region, resourceARN);
#                } else {
#                    helpers.addResult(results, 0, 'EBS Snapshot has tags', region, resourceARN);
#                }
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }