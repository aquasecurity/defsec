# METADATA
# title :"DynamoDB Accelerator Cluster Encryption"
# description: "Ensures DynamoDB Cluster Accelerator DAX clusters have encryption enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DynamoDB
#   severity: LOW
#   short_code: dax-cluster-encryption 
#   recommended_action: "Enable encryption for DAX cluster."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.dynamodb, function(region, rcb){
#            var describeClusters = helpers.addSource(cache, source,
#                ['dax', 'describeClusters', region]);
#
#            if (!describeClusters) return rcb();
#            if (describeClusters.err || !describeClusters.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for DAX clusters: ' + helpers.addError(describeClusters), region);
#                return rcb();
#            }
#
#            if (!describeClusters.data.length) {
#                helpers.addResult(results, 0, 'No DAX clusters found', region);
#                return rcb();
#            }
#
#            for (var c in describeClusters.data) {
#                var cluster = describeClusters.data[c];
#                var resource = cluster.ClusterArn;
#
#                if (cluster.SSEDescription &&
#                    cluster.SSEDescription.Status &&
#                    cluster.SSEDescription.Status.toUpperCase() === 'ENABLED') {
#                    helpers.addResult(results, 0,
#                        'Encryption is enabled for DAX :' + cluster.ClusterName, region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Encryption is not enabled for DAX :' + cluster.ClusterName, region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }