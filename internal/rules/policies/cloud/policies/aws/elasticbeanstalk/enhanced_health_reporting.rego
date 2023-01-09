# METADATA
# title :"Enhanced Health Reporting"
# description: "Ensure that Amazon Elastic Beanstalk (EB) environments have enhanced health reporting feature enabled."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ElasticBeanstalk
#   severity: LOW
#   short_code: enhanced-health-reporting 
#   recommended_action: "Modify Elastic Beanstalk environmentsand enable enhanced health reporting."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#
#        var regions = helpers.regions(settings);
#
#        async.each(regions.elasticbeanstalk, function(region, rcb){
#            var describeEnvironments = helpers.addSource(cache, source, ['elasticbeanstalk', 'describeEnvironments', region]);
#
#            if (!describeEnvironments) return rcb();
#
#            if (describeEnvironments.err || !describeEnvironments.data) {
#                helpers.addResult(results, 3,
#                    'Unable to query for Elastic Beanstalk environments', region);
#                return rcb();
#            }
#
#            if (!describeEnvironments.data.length) {
#                helpers.addResult(results, 0,
#                    'No Elastic Beanstalk environments found', region);
#                return rcb();
#            }
#
#            for (let environment of describeEnvironments.data) {
#                var resource = environment.EnvironmentArn;
#
#                if (environment.Health && environment.HealthStatus) {
#                    helpers.addResult(results, 0, `Enhanced Health Reporting feature is enabled for environment ${environment.EnvironmentName}.`, region, resource);
#                } else {
#                    helpers.addResult(results, 2, `Enhanced Health Reporting feature is not enabled for environment: ${environment.EnvironmentName}`, region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }