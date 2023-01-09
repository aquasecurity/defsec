# METADATA
# title :"DynamoDB Table Has Tags"
# description: "Ensure that DynamoDB tables have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:DynamoDB
#   severity: LOW
#   short_code: dynamo-table-has-tags 
#   recommended_action: "Modify DynamoDB table and add tags."
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
#            const ARNList = [];
#            for (let table of listTables.data){
#                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;
#                ARNList.push(resource);
#            }
#            helpers.checkTags(cache, 'DynamoDB table', ARNList, region, results);
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }