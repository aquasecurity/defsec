# METADATA
# title :"Access Analyzer Active Findings"
# description: "Ensure that IAM Access analyzer findings are reviewed and resolved by taking all necessary actions."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-work-with-findings.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: access-analyzer-active-findings 
#   recommended_action: "Investigate into active findings in your account and do the needful until you have zero active findings."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.accessanalyzer, function(region, rcb){        
#            var listAnalyzers = helpers.addSource(cache, source,
#                ['accessanalyzer', 'listAnalyzers', region]);
#
#            if (!listAnalyzers) return rcb();
#
#            if (listAnalyzers.err || !listAnalyzers.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for IAM Access Analyzer analyzers: ${helpers.addError(listAnalyzers)}`, region);
#                return rcb();
#            }
#
#            if (!listAnalyzers.data.length) {
#                helpers.addResult(results, 0, 'No IAM Access Analyzer analyzers found', region);
#                return rcb();
#            }
#
#            for (let analyzer of listAnalyzers.data) {
#                if (!analyzer.arn) continue;
#
#                let resource = analyzer.arn;
#
#                var listFindings = helpers.addSource(cache, source,
#                    ['accessanalyzer', 'listFindings', region, analyzer.arn]);
#
#                if (!listFindings || listFindings.err || !listFindings.data) {
#                    helpers.addResult(results, 3,
#                        `Unable to IAM Access Analyzer findings: ${helpers.addError(listFindings)}`,
#                        region, resource);
#                    continue;
#                } 
#                
#                let filtered = listFindings.data.findings.filter(finding => finding.status === 'ACTIVE');
#                if (!filtered.length) {
#                    helpers.addResult(results, 0,
#                        'Amazon IAM Access Analyzer has no active findings',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Amazon IAM Access Analyzer has active findings',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }