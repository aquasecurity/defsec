# METADATA
# title :"Lambda Public Access"
# description: "Ensures Lambda functions are not accessible globally"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Lambda
#   severity: LOW
#   short_code: lambda-public-access 
#   recommended_action: "Update the Lambda policy to prevent access from the public."
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
#                    'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
#                return rcb();
#            }
#
#            if (!listFunctions.data.length) {
#                helpers.addResult(results, 0, 'No Lambda functions found', region);
#                return rcb();
#            }
#
#            for (var f in listFunctions.data) {
#                var func = listFunctions.data[f];
#                var arn = func.FunctionArn;
#
#                var policy = helpers.addSource(cache, source,
#                    ['lambda', 'getPolicy', region, func.FunctionName]);
#
#                var result = [0, ''];
#
#                if (!policy) {
#                    result = [3, 'Error querying for policy for function'];
#                } else if (policy.err) {
#                    if (policy.err.code && policy.err.code == 'ResourceNotFoundException') {
#                        result = [0, 'Function does not have an access policy'];
#                    } else {
#                        result = [3, 'Error querying for Lambda function policy: ' + helpers.addError(policy)];
#                    }
#                } else if (policy.data) {
#                    var normalized = helpers.normalizePolicyDocument(policy.data.Policy);
#
#                    var found = [];
#                    for (var n in normalized) {
#                        var statement = normalized[n];
#                        if (statement.Principal) {
#                            var isGlobal = helpers.globalPrincipal(statement.Principal);
#                            if (isGlobal) {
#                                for (var s in statement.Action) {
#                                    if (found.indexOf(statement.Action[s]) == -1) {
#                                        found.push(statement.Action[s]);
#                                    }
#                                }
#                            }
#                        }
#                    }
#
#                    if (found.length) {
#                        result = [2, 'Function policy allows global access to actions: ' + found.join(', ')];
#                    } else {
#                        result = [0, 'Function policy does not allow global access'];
#                    }
#                } else {
#                    result = [3, 'Unable to obtain Lambda function policy'];
#                }
#
#                helpers.addResult(results, result[0], result[1], region, arn);
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }