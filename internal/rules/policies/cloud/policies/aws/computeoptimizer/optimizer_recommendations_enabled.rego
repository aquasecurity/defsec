# METADATA
# title :"Compute Optimizer Recommendations Enabled"
# description: "Ensure that Compute Optimizer is enabled for your AWS account."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/compute-optimizer/latest/ug/what-is-compute-optimizer.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Compute Optimizer
#   severity: LOW
#   short_code: optimizer-recommendations-enabled 
#   recommended_action: "Enable Compute Optimizer Opt In options for current of all AWS account in your organization."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.computeoptimizer, function(region, rcb){
#            var getRecommendationSummaries = helpers.addSource(cache, source,
#                ['computeoptimizer', 'getRecommendationSummaries', region]);
#
#            if (!getRecommendationSummaries) return rcb();
#
#            if (getRecommendationSummaries && getRecommendationSummaries.err && getRecommendationSummaries.err.code &&
#                getRecommendationSummaries.err.code.toUpperCase() === 'OPTINREQUIREDEXCEPTION'){
#                helpers.addResult(results, 2, 
#                    'Compute Optimizer is not enabled', region);
#            } else if (getRecommendationSummaries.err || !getRecommendationSummaries.data || 
#                      !getRecommendationSummaries.data.length) {
#                helpers.addResult(results, 3,
#                    'Unable to get Compute Optimizer recommendation summaries: ' + helpers.addError(getRecommendationSummaries), region);       
#            } else {
#                helpers.addResult(results, 0,
#                    'Compute Optimizer is Enabled', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }