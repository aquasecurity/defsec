# METADATA
# title :"DMS Multi-AZ Feature Enabled"
# description: "Ensure that your Amazon Database Migration Service (DMS) replication instances are using Multi-AZ deployment configurations."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DMS
#   severity: LOW
#   short_code: dms-multi-a-z-feature-enabled 
#   recommended_action: "Enable Multi-AZ deployment feature in order to get high availability and failover support"
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
#                if (instance.MultiAZ) {
#                    helpers.addResult(results, 0,
#                        'DMS replication instance has Multi-AZ feature enabled',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'DMS replication instance does not have Multi-AZ feature enabled',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }