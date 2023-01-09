# METADATA
# title :"DynamoDB Table Backup Exists"
# description: "Ensures that Amazon DynamoDB tables are using on-demand backups."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/BackupRestore.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DynamoDB
#   severity: LOW
#   short_code: dynamo-table-backup-exists 
#   recommended_action: "Create on-demand backups for DynamoDB tables."
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
#                    `Unable to query for DynamoDB tables: ${helpers.addError(listTables)}`,
#                    region);
#                return rcb();
#            }
#
#            if (!listTables.data.length) {
#                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
#                return rcb();
#            }
#
#            for (let table of listTables.data){
#                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;
#
#                var listBackups = helpers.addSource(cache, source,
#                    ['dynamodb', 'listBackups', region, table]);
#    
#                if (!listBackups || listBackups.err || !listBackups.data || !listBackups.data.BackupSummaries) {
#                    helpers.addResult(results, 3,
#                        `Unable to query backups for DynamoDB table: ${helpers.addError(listBackups)}`,
#                        region, resource);
#                    continue;
#                }
#               
#                if (!listBackups.data.BackupSummaries.length) {
#                    helpers.addResult(results, 2, 'No backup exists for DynamoDB table', 
#                        region, resource);    
#                } else {
#                    helpers.addResult(results, 0, 'Backup exists for DynamoDB table', 
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }