# METADATA
# title :"DMS Auto Minor Version Upgrade"
# description: "Ensure that your Amazon Database Migration Service (DMS) replication instances have the Auto Minor Version Upgrade feature enabled"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.Modifying.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DMS
#   severity: LOW
#   short_code: auto-minor-version-upgrade 
#   recommended_action: "Enable Auto Minor Version Upgrade feature in order to automatically receive minor engine upgrades for improved performance and security"
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
#                if (instance.AutoMinorVersionUpgrade) {
#                    helpers.addResult(results, 0,
#                        'Replication instance has auto minor version upgrade enabled',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Replication instance does not have auto minor version upgrade enabled',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }