# METADATA
# title :"EBS Encrypted Snapshots"
# description: "Ensures EBS snapshots are encrypted at rest"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html#encryption-support
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EC2
#   severity: LOW
#   short_code: ebs-encrypted-snapshots 
#   recommended_action: "Configure volume encryption and delete unencrypted EBS snapshots."
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
#            var describeSnapshots = helpers.addSource(cache, source,
#                ['ec2', 'describeSnapshots', region]);
#
#            if (!describeSnapshots) return rcb();
#
#            if (describeSnapshots.err || !describeSnapshots.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for EBS Snapshots: ' + helpers.addError(describeSnapshots), region);
#                return rcb();
#            }
#
#            if (!describeSnapshots.data.length) {
#                helpers.addResult(results, 0, 'No EBS snapshots present', region);
#                return rcb();
#            }
#
#            describeSnapshots.data.forEach(function(snapshot){
#                var arn = 'arn:aws:ec2:' + region + ':' + snapshot.OwnerId + ':snapshot/' + snapshot.SnapshotId;
#                if (snapshot.Encrypted){
#                    helpers.addResult(results, 0, 'EBS snapshot is encrypted', region, arn);
#                } else {
#                    helpers.addResult(results, 2, 'EBS snapshot is unencrypted', region, arn);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }