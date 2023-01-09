# METADATA
# title :"API Gateway WAF Enabled"
# description: "Ensures that API Gateway APIs are associated with a Web Application Firewall."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:API Gateway
#   severity: LOW
#   short_code: apigateway-waf-enabled 
#   recommended_action: "Associate API Gateway API with Web Application Firewall"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#
#        async.each(regions.apigateway, function(region, rcb){
#            var getRestApis = helpers.addSource(cache, source,
#                ['apigateway', 'getRestApis', region]);
#
#            if (!getRestApis) return rcb();
#
#            if (getRestApis.err || !getRestApis.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for API Gateway Rest APIs: ${helpers.addError(getRestApis)}`, region);
#                return rcb();
#            }
#
#            if (!getRestApis.data.length) {
#                helpers.addResult(results, 0,
#                    'No API Gateway Rest APIs found', region);
#                return rcb();
#            }
#
#            async.each(getRestApis.data, function(api, cb){
#                if (!api.id) return cb();
#
#                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;
#
#                var getStages = helpers.addSource(cache, source,
#                    ['apigateway', 'getStages', region, api.id]);
#
#                if (!getStages || getStages.err || !getStages.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for API Gateway Rest API Stages: ${helpers.addError(getStages)}`,
#                        region, apiArn);
#                    return cb();
#                }
#
#                if (!getStages.data.item || !getStages.data.item.length) {
#                    helpers.addResult(results, 0,
#                        'No Rest API Stages found',
#                        region, apiArn);
#                    return cb();
#                }
#
#                getStages.data.item.forEach(stage => {
#                    if (!stage.stageName) return;
#
#                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;
#                    if (stage.webAclArn) {
#                        helpers.addResult(results, 0,
#                            'API Gateway Stage has WAF enable',
#                            region, stageArn);
#                    } else {
#                        helpers.addResult(results, 2,
#                            'API Gateway Stage does not have WAF enabled',
#                            region, stageArn);
#                    }
#                });
#
#                cb();
#            });
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }