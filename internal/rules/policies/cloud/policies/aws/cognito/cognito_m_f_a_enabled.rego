# METADATA
# title :"Cognito User Pool MFA enabled"
# description: "Ensure that Cognito user pool has MFA enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Cognito
#   severity: LOW
#   short_code: cognito-m-f-a-enabled 
#   recommended_action: "1. Enter the Cognito service. 2. Enter user pools and enable MFA from sign in experience."
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
#        async.each(regions.cognitoidentityserviceprovider, function(region, rcb){
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
#                const userPoolArn ='arn:' + awsOrGov + ':cognito-idp:' + region + ':' + accountId + ':userpool/' + userPool.Id;
#
#                var describeUserPool = helpers.addSource(cache, source,
#                    ['cognitoidentityserviceprovider', 'describeUserPool', region, userPool.Id]);
#
#                if (!describeUserPool || describeUserPool.err || !describeUserPool.data || !describeUserPool.data.UserPool){
#                    helpers.addResult(results, 3,
#                        'Unable to describe Cognito user pool: ' + helpers.addError(describeUserPool), region, userPoolArn);
#                    continue;
#                }
#
#                if (describeUserPool.data.UserPool.MfaConfiguration && describeUserPool.data.UserPool.MfaConfiguration.toUpperCase() == 'ON'){
#                    helpers.addResult(results, 0, 'User pool has MFA enabled', region, userPoolArn);
#                } else {
#                    helpers.addResult(results, 2, 'User pool does not have MFA enabled', region, userPoolArn);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }