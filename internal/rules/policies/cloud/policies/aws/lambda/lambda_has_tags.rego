# METADATA
# title :"Lambda Has Tags"
# description: "Ensure that AWS Lambda functions have tags associated."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lambda/latest/dg/configuration-tags.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Lambda
#   severity: LOW
#   short_code: lambda-has-tags 
#   recommended_action: "Modify Lambda function configurations and  add new tags"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.lambda, function(region, rcb){
#            var listFunctions = helpers.addSource(cache, source,
#                ['lambda', 'listFunctions', region]);
#
#            if (!listFunctions) return rcb();
#
#            if (listFunctions.err || !listFunctions.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Lambda functions: ${helpers.addError(listFunctions)}`, region);
#                return rcb();
#            }
#
#            if (!listFunctions.data.length) {
#                helpers.addResult(results, 0, 'No Lambda functions found', region);
#                return rcb();
#            }
#
#            let existingLambdaARNList = [];
#            for (var lambdaFunc of listFunctions.data) {
#                if (!lambdaFunc.FunctionArn) continue;
#                existingLambdaARNList.push(lambdaFunc.FunctionArn);
#            }
#            if (existingLambdaARNList.length){
#                helpers.checkTags(cache, 'Lambda function', existingLambdaARNList, region, results);
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }