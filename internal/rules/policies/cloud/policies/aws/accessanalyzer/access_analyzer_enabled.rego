# METADATA
# title :"Access Analyzer Enabled"
# description: "Ensure that IAM Access analyzer is enabled for all regions."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:IAM
#   severity: LOW
#   short_code: access-analyzer-enabled 
#   recommended_action: "Enable Access Analyzer for all regions"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#        async.each(regions.accessanalyzer, function(region, rcb){
#            var listAnalyzers = helpers.addSource(cache, source,
#                ['accessanalyzer', 'listAnalyzers', region]);
#            
#            if (!listAnalyzers) return rcb();
#
#            if (listAnalyzers.err || !listAnalyzers.data) {
#                helpers.addResult(results, 3,
#                    'Unable to list Access Analyzers: ' + helpers.addError(listAnalyzers), region);
#                return rcb();
#            }
#
#            if (!listAnalyzers.data.length) {
#                helpers.addResult(results, 2,
#                    'Access Analyzer is not configured', region);
#                return rcb();
#            }
#
#            var found = listAnalyzers.data.find(analyzer => analyzer.status.toLowerCase() == 'active');
#            if (found) {
#                helpers.addResult(results, 0,
#                    'Access Analyzer is enabled', region, found.arn);
#            } else {
#                helpers.addResult(results, 2,
#                    'Access Analyzer is not enabled', region);
#            }
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }