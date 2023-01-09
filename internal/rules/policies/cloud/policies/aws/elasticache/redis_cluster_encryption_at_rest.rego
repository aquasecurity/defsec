# METADATA
# title :"ElastiCache Redis Cluster Encryption At-Rest"
# description: "Ensure that your Amazon ElastiCache Redis clusters are encrypted to increase data security."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElastiCache
#   severity: LOW
#   short_code: redis-cluster-encryption-at-rest 
#   recommended_action: "Enable encryption for ElastiCache cluster data-at-rest"
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
#            desiredEncryptionLevelString: settings.ec_cluster_target_encryption_level || this.settings.ec_cluster_target_encryption_level.default
#        };
#
#        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
#        var currentEncryptionLevel;
#
#        async.each(regions.elasticache, function(region, rcb){
#            var describeCacheClusters = helpers.addSource(cache, source,
#                ['elasticache', 'describeCacheClusters', region]);
#
#            if (!describeCacheClusters) return rcb();
#
#            if (describeCacheClusters.err || !describeCacheClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to list ElastiCache clusters : ${helpers.addError(describeCacheClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeCacheClusters.data.length) {
#                helpers.addResult(results, 0,
#                    'No ElastiCache clusters found', region);
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
#            for (let cluster of describeCacheClusters.data) {
#                if (!cluster.ARN) continue;
#
#                let resource = cluster.ARN;
#
#                if (cluster.Engine !== 'redis') {
#                    helpers.addResult(results, 0, `Encryption is not supported for ${cluster.Engine}`, region, resource);
#                    continue;
#                }
#
#                if (cluster.AtRestEncryptionEnabled) {
#                    let describeReplicationGroups = helpers.addSource(cache, source,
#                        ['elasticache', 'describeReplicationGroups', region, cluster.ReplicationGroupId]);
#
#                    if (!describeReplicationGroups || describeReplicationGroups.err || !describeReplicationGroups.data ||
#                        !describeReplicationGroups.data.ReplicationGroups || !describeReplicationGroups.data.ReplicationGroups.length) {
#                        helpers.addResult(results, 3,
#                            `Unable to describe replication groups for cluster: ${helpers.addError(describeReplicationGroups)}`, region, resource);
#                        continue;
#                    }
#                
#                    if (describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId) {
#                        var kmsKeyId = describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId.split('/')[1] ? describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId.split('/')[1] : describeReplicationGroups.data.ReplicationGroups[0].KmsKeyId;
#
#                        var describeKey = helpers.addSource(cache, source,
#                            ['kms', 'describeKey', region, kmsKeyId]);
#
#                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
#                            helpers.addResult(results, 3,
#                                `Unable to query KMS key: ${helpers.addError(describeKey)}`,
#                                region, kmsKeyId);
#                            continue;
#                        }
#
#                        currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
#                    } else {
#                        currentEncryptionLevel = 2; //awskms
#                    }
#
#                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];
#
#                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
#                        helpers.addResult(results, 0,
#                            `ElastiCache Redis Cluster is encrypted with ${currentEncryptionLevelString} \
#                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `ElastiCache Redis Cluster is encrypted with ${currentEncryptionLevelString} \
#                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        'Cluster does not have at-rest encryption enabled', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }