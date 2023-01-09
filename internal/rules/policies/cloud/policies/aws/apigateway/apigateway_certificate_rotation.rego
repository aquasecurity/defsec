# METADATA
# title :"API Gateway Certificate Rotation"
# description: "Ensures that Amazon API Gateway APIs have certificates with expiration date more than the rotation limit."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:API Gateway
#   severity: LOW
#   short_code: apigateway-certificate-rotation 
#   recommended_action: "Rotate the certificate attached to API Gateway API"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var api_certificate_rotation_limit = parseInt(settings.api_certificate_rotation_limit || this.settings.api_certificate_rotation_limit.default);
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
#            async.each(getRestApis.data, function(api, acb){
#                if (!api.id) return acb();
#                var apiArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}`;
#
#                var getStages = helpers.addSource(cache, source,
#                    ['apigateway', 'getStages', region, api.id]);
#
#                if (!getStages || getStages.err || !getStages.data || !getStages.data.item) {
#                    helpers.addResult(results, 3,
#                        `Unable to query for API Gateway Rest API Stages: ${helpers.addError(getStages)}`,
#                        region, apiArn);
#                    return acb();
#                }
#
#                if (!getStages.data.item.length) {
#                    helpers.addResult(results, 0,
#                        'No Rest API Stages found',
#                        region, apiArn);
#                    return acb();
#                }
#
#                getStages.data.item.forEach(stage => {
#                    if (!stage.stageName || !stage.clientCertificateId) return;
#
#                    var stageArn = `arn:${awsOrGov}:apigateway:${region}::/restapis/${api.id}/stages/${stage.stageName}`;
#
#                    var getClientCertificate = helpers.addSource(cache, source,
#                        ['apigateway', 'getClientCertificate', region, stage.clientCertificateId]);
#
#                    if (!getClientCertificate || getClientCertificate.err || !getClientCertificate.data) {
#                        helpers.addResult(results, 3,
#                            `Unable to query for API Gateway Rest API Stage Client Certificate: ${helpers.addError(getClientCertificate)}`,
#                            region, stageArn);
#                        return;
#                    }
#
#                    if (!getClientCertificate.data.expirationDate) {
#                        helpers.addResult(results, 0,
#                            'No Client Certificate information found',
#                            region, stageArn);
#                        return;
#                    }
#
#                    var then = new Date(getClientCertificate.data.expirationDate);
#                    var difference = Math.round((new Date(then).getTime() - new Date().getTime())/(24*60*60*1000));
#
#                    if (difference > api_certificate_rotation_limit) {
#                        helpers.addResult(results, 0,
#                            `API Gateway API stage does not need client certificate rotation as it expires in ${difference} days ` +
#                            `of ${api_certificate_rotation_limit} days limit`,
#                            region, stageArn);
#                    } else if (difference >= 0){
#                        helpers.addResult(results, 2,
#                            `API Gateway API stage client certificate needs rotation as it expires in ${difference} days ` +
#                            `of ${api_certificate_rotation_limit} days limit`,
#                            region, stageArn);
#                    } else {
#                        helpers.addResult(results, 2,
#                            `API Gateway API stage client certificate needs rotation as it expired ${Math.abs(difference)} days ago`,
#                            region, stageArn);
#                    }
#                });
#                
#                acb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }