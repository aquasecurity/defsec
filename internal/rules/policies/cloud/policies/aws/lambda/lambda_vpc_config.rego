# METADATA
# title :"Lambda VPC Config"
# description: "Ensures Lambda functions are created in a VPC."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lambda/latest/dg/vpc.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Lambda
#   severity: LOW
#   short_code: lambda-vpc-config 
#   recommended_action: "Update the Lambda function with a VPC configuration."
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
#            lambda_whitelist: settings.lambda_whitelist || this.settings.lambda_whitelist.default
#        };
#
#        if (config.lambda_whitelist &&
#            config.lambda_whitelist.length) {
#            config.lambda_whitelist = config.lambda_whitelist.split(',');
#        } else {
#            config.lambda_whitelist = [];
#        }
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
#                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
#                var lambdaFunction = listFunctions.data[f];
#                let whitelisted = false;
#                if (config.lambda_whitelist.length) {
#                    config.lambda_whitelist.forEach(whitelist => {
#                        if (lambdaFunction.FunctionName.indexOf(whitelist) > -1) {
#                            whitelisted = true;
#                        }
#                    });
#                }
#
#                if (whitelisted) {
#                    helpers.addResult(results, 0,
#                        'The function ' + lambdaFunction.FunctionName + ' is whitelisted.',
#                        region, lambdaFunction.FunctionArn);
#                } else {
#                    if (lambdaFunction.VpcConfig && lambdaFunction.VpcConfig.VpcId) {
#                        helpers.addResult(results, 0,
#                            'Function is being launched into a VPC',
#                            region, lambdaFunction.FunctionArn);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Function is not being launched into a VPC',
#                            region, lambdaFunction.FunctionArn);
#                    }
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }