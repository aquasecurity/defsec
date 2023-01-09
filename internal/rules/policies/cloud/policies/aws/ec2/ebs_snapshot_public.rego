# METADATA
# title :"Amazon EBS Public Snapshots"
# description: "Ensure that Amazon EBS volume snapshots are not shared to all AWS accounts."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-snapshot-public 
#   recommended_action: "Modify the permissions of public snapshots to remove public access."
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
#                helpers.addResult(results, 0, 'No EBS snapshots present', region);
#                return rcb();
#            }
#
#            var publicSnapshots = [];
#            describeSnapshots.data.forEach(snapshot => {
#                if (!snapshot.SnapshotId) return;
#
#                var resource = `arn:${awsOrGov}:${region}:${snapshot.OwnerId}:snapshot/${snapshot.SnapshotId}`;
#
#                var describeSnapshotAttribute = helpers.addSource(cache, source,
#                    ['ec2', 'describeSnapshotAttribute', region, snapshot.SnapshotId]);
#
#                if (!describeSnapshotAttribute ||
#                    describeSnapshotAttribute.err ||
#                    !describeSnapshotAttribute.data ||
#                    !describeSnapshotAttribute.data.CreateVolumePermissions) {
#                    helpers.addResult(results, 3,
#                        `Unable to query EBS snapshot attribute: ${helpers.addError(describeSnapshotAttribute)}`, region, resource);
#                    return;
#                }
#                
#                if (describeSnapshotAttribute.data.CreateVolumePermissions.length) {
#                    for (var p in describeSnapshotAttribute.data.CreateVolumePermissions) {
#                        var perm = describeSnapshotAttribute.data.CreateVolumePermissions[p];
#
#                        if (perm.Group && perm.Group === 'all') {
#                            publicSnapshots.push(resource);
#                            break;
#                        }
#                    }
#                }
#            });
#
#            if (publicSnapshots.length > 20) {
#                helpers.addResult(results, 2, 'More than 20 EBS snapshots are publicly shared', region);
#            } else if (publicSnapshots.length) {
#                for (var ps in publicSnapshots) {
#                    helpers.addResult(results, 2,
#                        'EBS snapshot is publicly shared',
#                        region, publicSnapshots[ps]);
#                }
#            } else {
#                helpers.addResult(results, 0,
#                    'No public EBS snapshots found', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }