# METADATA
# title :"AWS Config Complaint Rules"
# description: "Ensures that all the evaluation results returned from the Amazon Config rules created within your AWS account are compliant."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ConfigService
#   severity: LOW
#   short_code: config-complaint-rules 
#   recommended_action: "Enable the AWS Config Service rules for compliance checks and close security gaps."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.configservice, function(region, rcb){        
#            var describeConfigRules = helpers.addSource(cache, source,
#                ['configservice', 'describeConfigRules', region]);           
#
#            if (!describeConfigRules) return rcb();
#
#            if (describeConfigRules.err || !describeConfigRules.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query Config Rules: ' + helpers.addError(describeConfigRules), region);
#                return rcb();
#            }
#
#            if (!describeConfigRules.data.length) {
#                helpers.addResult(results, 0, 'No Config Rules found', region);
#                return rcb();
#            }
#            
#            for (let rule of describeConfigRules.data) {
#                if (!rule.ConfigRuleArn) continue;
#               
#                let resource = rule.ConfigRuleArn;
#                var getComplianceDetailsByConfigRule = helpers.addSource(cache, source,
#                    ['configservice', 'getComplianceDetailsByConfigRule', region, rule.ConfigRuleName]);
#                
#                if (!getComplianceDetailsByConfigRule || getComplianceDetailsByConfigRule.err || !getComplianceDetailsByConfigRule.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to get Evaluation Results: ${helpers.addError(getComplianceDetailsByConfigRule)}`,
#                        region, resource);
#                    continue;
#                }
#
#                if (!getComplianceDetailsByConfigRule.data.EvaluationResults ||
#                    !getComplianceDetailsByConfigRule.data.EvaluationResults.length){
#                    helpers.addResult(results, 0, 'Amazon Config rule returns compliant evaluation results',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2, 'Amazon Config rule returns noncompliant evaluation results',
#                        region, resource);
#                }
#            }
#
#            rcb();  
#        }, function(){
#            callback(null, results, source);
#        });
#    }