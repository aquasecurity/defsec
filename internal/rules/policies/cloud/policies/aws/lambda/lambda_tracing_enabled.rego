# METADATA
# title :"Lambda Tracing Enabled"
# description: "Ensures AWS Lambda functions have active tracing for X-Ray."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Lambda
#   severity: LOW
#   short_code: lambda-tracing-enabled 
#   recommended_action: "Modify Lambda functions to activate tracing"
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
#                    `Unable to query for Lambda functions: ${helpers.addError(listFunctions)}`, region);
#                return rcb();
#            }
#
#            if (!listFunctions.data.length) {
#                helpers.addResult(results, 0, 'No Lambda functions found', region);
#                return rcb();
#            }
#
#            for (var lambdaFunc of listFunctions.data) {
#                if (!lambdaFunc.FunctionArn) continue;
#                var resource = lambdaFunc.FunctionArn;
#
#                let whitelisted = false;
#                if (config.lambda_whitelist.length) {
#                    config.lambda_whitelist.forEach(whitelist => {
#                        if (lambdaFunc.FunctionName.indexOf(whitelist) > -1) {
#                            whitelisted = true;
#                        }
#                    });
#                }
#
#                if (whitelisted) {
#                    helpers.addResult(results, 0,
#                        'The function ' + lambdaFunc.FunctionName + ' is whitelisted.',
#                        region, lambdaFunc.FunctionArn);
#                } else {
#                    if (lambdaFunc.TracingConfig &&
#                        lambdaFunc.TracingConfig.Mode &&
#                        lambdaFunc.TracingConfig.Mode.toUpperCase() === 'ACTIVE') {
#                        helpers.addResult(results, 0,
#                            'Function has active tracing', region, resource);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'Function does not have active tracing', region, resource);
#                    }
#                }
#            }
#            
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }