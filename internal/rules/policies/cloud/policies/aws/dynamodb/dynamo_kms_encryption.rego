# METADATA
# title :"DynamoDB KMS Encryption"
# description: "Ensures DynamoDB tables are encrypted using a customer-owned KMS key."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DynamoDB
#   severity: LOW
#   short_code: dynamo-kms-encryption 
#   recommended_action: "Create a new DynamoDB table using a CMK KMS key."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        async.each(regions.dynamodb, function(region, rcb){
#            var listTables = helpers.addSource(cache, source,
#                ['dynamodb', 'listTables', region]);
#
#            if (!listTables) return rcb();
#
#            if (listTables.err || !listTables.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for DynamoDB tables: ' + helpers.addError(listTables), region);
#                return rcb();
#            }
#
#            if (!listTables.data.length) {
#                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
#                return rcb();
#            }
#
#            for (var i in listTables.data) {
#                var table = listTables.data[i];
#
#                var describeTable = helpers.addSource(cache, source,
#                    ['dynamodb', 'describeTable', region, table]);
#
#                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;
#
#                if (describeTable.err || !describeTable.data || !describeTable.data.Table) {
#                    helpers.addResult(results, 3,
#                        'Unable to describe DynamoDB table: ' + helpers.addError(describeTable), region, resource);
#                    return rcb();
#                }
#
#
#                if (describeTable.data.Table.SSEDescription &&
#                    describeTable.data.Table.SSEDescription.Status &&
#                    describeTable.data.Table.SSEDescription.Status.toUpperCase() === 'ENABLED') {
#                    helpers.addResult(results, 0,
#                        'Table encryption is enabled with a KMS master key', region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Table is using default encryption with AWS-owned key', region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }