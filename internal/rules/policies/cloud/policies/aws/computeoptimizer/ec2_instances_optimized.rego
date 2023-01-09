# METADATA
# title :"EC2 Instances Optimized"
# description: "Ensure that Compute Optimizer does not have active recommendation summaries for over-provisioned or under-provisioned EC2 instances."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ec2-recommendations.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:Compute Optimizer
#   severity: LOW
#   short_code: ec2-instances-optimized 
#   recommended_action: "Resolve Compute Optimizer recommendations for EC2 instances."
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
#            if (getRecommendationSummaries && getRecommendationSummaries.err &&
#                getRecommendationSummaries.err.code &&
#                getRecommendationSummaries.err.code.toUpperCase() === 'OPTINREQUIREDEXCEPTION'){
#                helpers.addResult(results, 0, 
#                    'Compute Optimizer is not enabled', region);
#                return rcb();
#            }
# 
#            if (getRecommendationSummaries.err || !getRecommendationSummaries.data) {
#                helpers.addResult(results, 3,
#                    'Unable to get recommendation summaries: ' + helpers.addError(getRecommendationSummaries), region);
#                return rcb();
#            }
#
#            if (!getRecommendationSummaries.data.length) {
#                helpers.addResult(results, 0, 
#                    'No Compute Optimizer recommendation summaries found', region);
#                return rcb();
#            }
#
#            let findings = getRecommendationSummaries.data.find(resourceType => resourceType.recommendationResourceType &&
#                resourceType.recommendationResourceType.toUpperCase() === 'EC2INSTANCE');
#            if (findings) {
#                let underProvisioned = findings.summaries.find(underProv => underProv.name === 'UNDER_PROVISIONED' );
#                let optimized = findings.summaries.find(opt => opt.name === 'OPTIMIZED' );
#                let overProvisioned = findings.summaries.find(overProv => overProv.name === 'OVER_PROVISIONED' );
#
#                if (!underProvisioned.value && !overProvisioned.value && !optimized.value){
#                    helpers.addResult(results, 0,
#                        'EC2 instances have no recommendations enabled', region);
#                } else if (underProvisioned.value || overProvisioned.value){
#                    helpers.addResult(results, 2,
#                        `Found ${underProvisioned.value} under-provisioned and ${overProvisioned.value} over-provisioned EC2 instances`, region);
#                } else {
#                    helpers.addResult(results, 0,
#                        'All EC2 instances are optimized', region);
#                }
#            } else {
#                helpers.addResult(results, 2,
#                    'Recommendation summaries are not configured for EC2 instances', region);
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }