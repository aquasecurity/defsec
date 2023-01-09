# METADATA
# title :"DocumentDB Cluster Backup Retention"
# description: "Ensure that your Amazon DocumentDB clusters have set a minimum backup retention period."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-modify.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DocumentDB
#   severity: LOW
#   short_code: docdb-cluster-backup-retention 
#   recommended_action: "Modify DocumentDb cluster to configure sufficient backup retention period."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var doc_db_backup_retention_threshold = parseInt(settings.doc_db_backup_retention_threshold || this.settings.doc_db_backup_retention_threshold.default); 
#
#        async.each(regions.docdb, function(region, rcb){
#            var describeDBClusters = helpers.addSource(cache, source,
#                ['docdb', 'describeDBClusters', region]);
#
#            if (!describeDBClusters) return rcb();
#
#            if (describeDBClusters.err || !describeDBClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list DocumentDB clusters: ${helpers.addError(describeDBClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeDBClusters.data.length) {
#                helpers.addResult(results, 0,
#                    'No DocumentDB clusters found', region);
#                return rcb();
#            }
#            
#            for (let cluster of describeDBClusters.data) {
#                if (!cluster.DBClusterArn) continue;
#
#                let resource = cluster.DBClusterArn;
#
#                if (cluster.BackupRetentionPeriod && cluster.BackupRetentionPeriod >=  doc_db_backup_retention_threshold) {
#                    helpers.addResult(results, 0,
#                        `DocumentDB cluster has a backup retention period of ${cluster.BackupRetentionPeriod} of ${doc_db_backup_retention_threshold} days limit`,
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        `DocumentDB cluster has a backup retention period of ${cluster.BackupRetentionPeriod} of ${doc_db_backup_retention_threshold} days limit`,
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }