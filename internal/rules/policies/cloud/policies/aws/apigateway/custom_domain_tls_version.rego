# METADATA
# title :"Custom Domain TLS Version"
# description: "Ensure API Gateway custom domains are using current minimum TLS version."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:API Gateway
#   severity: LOW
#   short_code: custom-domain-tls-version 
#   recommended_action: "Modify API Gateway custom domain security policy and specify new TLS version."
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
#            var getDomainNames = helpers.addSource(cache, source,
#                ['apigateway', 'getDomainNames', region]);
#
#            if (!getDomainNames) return rcb();
#
#            if (getDomainNames.err || !getDomainNames.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for API Gateway Custom Domain: ${helpers.addError(getDomainNames)}`, region);
#                return rcb();
#            }
#    
#            if (!getDomainNames.data.length) {
#                helpers.addResult(results, 0, 'No API Gateway Custom Domains found', region);
#                return rcb();
#            }
#            for (let domain of getDomainNames.data){
#                if (!domain.domainName) continue;
#
#                var domainArn = `arn:${awsOrGov}:apigateway:${region}::/domainnames/${domain.domainName}`;
#
#                if (domain.securityPolicy && domain.securityPolicy === 'TLS_1_2'){
#                    helpers.addResult(results, 0,
#                        `API Gateway Custom Domain is using current minimum TLS version ${domain.securityPolicy}`, region, domainArn);
#                } else {
#                    helpers.addResult(results, 2,
#                        `API Gateway Custom Domain is using deprecated TLS version ${domain.securityPolicy}`, region, domainArn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }