# METADATA
# title :"Redshift Cluster CMK Encryption"
# description: "Ensures Redshift clusters are encrypted using KMS customer master keys (CMKs)"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Redshift
#   severity: LOW
#   short_code: redshift-cluster-cmk-encrypted 
#   recommended_action: "Update Redshift clusters encryption configuration to use KMS CMKs instead of AWS managed-keys."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.redshift, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['redshift', 'describeClusters', region]);
#
#            if (!describeClusters) return rcb();
#
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0, 'No Redshift clusters found', region);
#                return rcb();
#            }
#
#            var listAliases = helpers.addSource(cache, source,
#                ['kms', 'listAliases', region]);
#
#            if (!listAliases || listAliases.err || !listAliases.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for KMS aliases: ${helpers.addError(listAliases)}`,
#                    region);
#                return rcb();
#            }
#
#            var aliasId;
#            var kmsAliases = {};
#            //Create an object where key is kms key ARN and value is alias name
#            listAliases.data.forEach(function(alias){
#                if (alias.AliasArn && alias.TargetKeyId) {
#                    aliasId = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
#                    kmsAliases[aliasId] = alias.AliasName;
#                }
#            });
#
#            for (var c in describeClusters.data) {
#                var cluster = describeClusters.data[c];
#                if (!cluster.ClusterIdentifier) continue;
#
#                var clusterIdentifier = cluster.ClusterIdentifier;
#                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
#
#                if (cluster.Encrypted && cluster.KmsKeyId) {
#                    if (kmsAliases[cluster.KmsKeyId]) {
#                        if (kmsAliases[cluster.KmsKeyId] === 'alias/aws/rds'){
#                            helpers.addResult(results, 2,
#                                `Redshift cluster "${cluster.ClusterIdentifier}"is not encrypted using KMS customer master key(CMK)`,
#                                region, resource);
#                        } else {
#                            helpers.addResult(results, 0,
#                                `Redshift cluster "${cluster.ClusterIdentifier}"is not encrypted using KMS customer master key(CMK)`,
#                                region, resource);
#                        }
#                    } else {
#                        helpers.addResult(results, 2,
#                            `Redshift cluster encryption key "${cluster.KmsKeyId}" not found`,
#                            region, resource);
#                    }
#                } else {
#                    helpers.addResult(results, 2,
#                        `Redshift cluster "${cluster.ClusterIdentifier}" does not have encryption enabled`,
#                        region, resource);
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }