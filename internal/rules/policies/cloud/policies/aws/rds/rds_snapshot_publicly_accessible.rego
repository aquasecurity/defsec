# METADATA
# title :"RDS Snapshot Publicly Accessible"
# description: "Ensure that Amazon RDS database snapshots are not publicly exposed."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:RDS
#   severity: LOW
#   short_code: rds-snapshot-publicly-accessible 
#   recommended_action: "Ensure Amazon RDS database snapshot is not publicly accessible and available for any AWS account to copy or restore it."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.rds, function(region, rcb){
#            var describeDBSnapshots = helpers.addSource(cache, source,
#                ['rds', 'describeDBSnapshots', region]);
#
#            if (!describeDBSnapshots) return rcb();
#
#            if (describeDBSnapshots.err || !describeDBSnapshots.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for RDS snapshots: ' + helpers.addError(describeDBSnapshots), region);
#                return rcb();
#            }
#
#            if (!describeDBSnapshots.data.length) {
#                helpers.addResult(results, 0, 'No RDS snapshots found', region);
#                return rcb();
#            }
#
#            describeDBSnapshots.data.forEach(snapshot => {
#                if (!snapshot.DBSnapshotIdentifier) return;
#
#                var snapshotIdentifier = snapshot.DBSnapshotIdentifier;
#                var resource = snapshot.DBSnapshotArn;
#
#                var describeDBSnapshotAttributes = helpers.addSource(cache, settings,
#                    ['rds', 'describeDBSnapshotAttributes', region, snapshotIdentifier]);
#
#                if (!describeDBSnapshotAttributes ||
#                    describeDBSnapshotAttributes.err ||
#                    !describeDBSnapshotAttributes.data ||
#                    !describeDBSnapshotAttributes.data.DBSnapshotAttributesResult) {
#                    helpers.addResult(results, 3,
#                        `Unable to describe Snapshot attributes "${snapshotIdentifier}": ${helpers.addError(describeDBSnapshotAttributes)}`,
#                        region, resource);
#
#                    return;
#                }
#
#                let publicSnapshot;
#                if (describeDBSnapshotAttributes.data.DBSnapshotAttributesResult.DBSnapshotAttributes) {
#                    publicSnapshot = describeDBSnapshotAttributes.data.DBSnapshotAttributesResult.DBSnapshotAttributes.find(
#                        attribute => attribute.AttributeValues && attribute.AttributeValues.includes('all')
#                    );
#                }
#
#                if (publicSnapshot){
#                    helpers.addResult(results, 2,
#                        'RDS Snapshot is publicly exposed',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 0,
#                        'RDS Snapshot is not publicly exposed',
#                        region, resource);
#                }
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }