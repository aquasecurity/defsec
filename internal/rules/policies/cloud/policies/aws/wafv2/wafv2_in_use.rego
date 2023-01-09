# METADATA
# title :"AWS WAFV2 In Use"
# description: "Ensure that AWS Web Application Firewall V2 (WAFV2) is in use to achieve availability and security for AWS-powered web applications."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:WAF
#   severity: LOW
#   short_code: wafv2-in-use 
#   recommended_action: "Create one or more WAF ACLs with proper actions and rules"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = { };
#        var regions = helpers.regions(settings);
#
#        async.each(regions.wafregional, function(region, rcb){
#            var listWebACLs = helpers.addSource(cache, source,
#                ['wafv2', 'listWebACLs', region]);
#
#            if (!listWebACLs) return rcb();
#
#            if (listWebACLs.err || !listWebACLs.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list WAFV2 web ACLs: ' + helpers.addError(listWebACLs), region);
#                return rcb();
#            }
#
#            if (!listWebACLs.data.length) {
#                helpers.addResult(results, 2, 'WAFV2 is not enabled', region);
#            } else {
#                helpers.addResult(results, 0, 'WAFV2 is enabled', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }