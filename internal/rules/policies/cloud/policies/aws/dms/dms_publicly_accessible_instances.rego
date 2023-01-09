# METADATA
# title :"DMS Publicly Accessible Instances"
# description: "Ensure that Amazon Database Migration Service (DMS) instances are not publicly accessible."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.PublicPrivate.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DMS
#   severity: LOW
#   short_code: dms-publicly-accessible-instances 
#   recommended_action: "Ensure that DMS replication instances have only private IP address and not public IP address"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.dms, function(region, rcb){
#            var describeReplicationInstances = helpers.addSource(cache, source,
#                ['dms', 'describeReplicationInstances', region]);
#
#            if (!describeReplicationInstances) return rcb();
#
#            if (describeReplicationInstances.err || !describeReplicationInstances.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list DMS replication instances: ${helpers.addError(describeReplicationInstances)}`, region);
#                return rcb();
#            }
#
#            if (!describeReplicationInstances.data.length) {
#                helpers.addResult(results, 0,
#                    'No DMS replication instances found', region);
#                return rcb();
#            }
#
#            for (let instance of describeReplicationInstances.data) {
#                if (!instance.ReplicationInstanceArn) continue;
#
#                let resource = instance.ReplicationInstanceArn;
#
#                if (!instance.PubliclyAccessible) {
#                    helpers.addResult(results, 0,
#                        'DMS replication instance is not publicly accessible.',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'DMS replication instance is publicly accessible.',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }