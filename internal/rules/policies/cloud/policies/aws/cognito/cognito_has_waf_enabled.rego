# METADATA
# title :"Cognito User Pool WAF Enabled"
# description: "Ensure that Cognito User Pool has WAF enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-waf.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Cognito
#   severity: LOW
#   short_code: cognito-has-waf-enabled 
#   recommended_action: "1. Enter the Cognito service. 2. Enter user pools and enable WAF from properties."
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
#        async.each(regions.cognitoidentityserviceprovider, function(region, rcb) {
#            var userPools = helpers.addSource(cache, source,
#                ['cognitoidentityserviceprovider', 'listUserPools', region]);
#
#            if (!userPools) return rcb();
#
#            if (userPools.err || !userPools.data){
#                helpers.addResult(results, 3,  'Unable to query Cognito user pools: ' + helpers.addError(userPools), region);
#                return rcb();
#            }
#
#            if (!userPools.data.length){
#                helpers.addResult(results, 0, 'No Cognito user pools found', region);
#                return rcb();
#            }
#
#            for (let userPool of userPools.data) {
#                if (!userPool.Id) continue;
#                
#                var arn = 'arn:' + awsOrGov + ':cognito-idp:' + region + ':' + accountId + ':userpool/' + userPool.Id;
#
#                var webACLResource = helpers.addSource(cache, source,
#                    ['wafv2', 'getWebACLForCognitoUserPool', region, userPool.Id]);
#              
#                if (!webACLResource || webACLResource.err || !webACLResource.data){
#                    helpers.addResult(results, 3,
#                        'Unable to get WebACL resource for cognito user pool: ' + helpers.addError(webACLResource), region, arn);
#                    continue;
#                }
#                if (webACLResource.data.WebACL){
#                    helpers.addResult(results, 0, 'User pool has WAFV2 enabled', region, arn);
#                } else {
#                    helpers.addResult(results, 2, 'User pool does not have WAFV2 enabled', region, arn);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }