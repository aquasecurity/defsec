# METADATA
# title :"DocumentDB Cluster Encrypted"
# description: "Ensure that data at-rest in encrypted in AWS DocumentDB clusters using desired encryption level."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DocumentDB
#   severity: LOW
#   short_code: docdb-cluster-encrypted 
#   recommended_action: "Modify DocumentDB cluster at-rest encryption configuration to use desired encryption key"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            desiredEncryptionLevelString: settings.documentdb_cluster_desired_encryption_level || this.settings.documentdb_cluster_desired_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
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
#            var listKeys = helpers.addSource(cache, source,
#                ['kms', 'listKeys', region]);
#
#            if (!listKeys || listKeys.err || !listKeys.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
#                return rcb();
#            }
#            
#            for (let cluster of describeDBClusters.data) {
#                if (!cluster.DBClusterArn) continue;
#
#                let resource = cluster.DBClusterArn;
#
#                if (cluster.KmsKeyId) {
#                    var kmsKeyId = cluster.KmsKeyId.split('/')[1] ? cluster.KmsKeyId.split('/')[1] : cluster.KmsKeyId;
#
#                    var describeKey = helpers.addSource(cache, source,
#                        ['kms', 'describeKey', region, kmsKeyId]); 
#
#                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                        helpers.addResult(results, 3,
#                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                            region, cluster.KmsKeyId);
#                        continue;
#                    }
#
#                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `DocumentDB cluster is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `DocumentDB cluster is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'DynamoDB cluster does not have at-rest encryption enabled',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }