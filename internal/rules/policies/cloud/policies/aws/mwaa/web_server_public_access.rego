# METADATA
# title :"Web Server Public Access"
# description: "Ensures web access to the Apache Airflow UI in your MWAA environment is not public."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/mwaa/latest/userguide/vpc-create.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:MWAA
#   severity: LOW
#   short_code: web-server-public-access 
#   recommended_action: "Modify Amazon MWAA environments to set web server access mode to be private only"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var defaultRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);
#
#        async.each(regions.mwaa, function(region, rcb){
#            var listEnvironments = helpers.addSource(cache, source,
#                ['mwaa', 'listEnvironments', region]);
#
#            if (!listEnvironments) return rcb();
#
#            if (listEnvironments.err || !listEnvironments.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for Airflow environments: ${helpers.addError(listEnvironments)}`, region);
#                return rcb();
#            }
#
#            if (!listEnvironments.data.length) {
#                helpers.addResult(results, 0, 'No Airflow environments found', region);
#                return rcb();
#            }
#
#            async.each(listEnvironments.data, function(airflowEnv, cb){
#                var resource = `arn:${awsOrGov}:airflow:${region}:${accountId}:environment/${airflowEnv}`;
#
#                var getEnvironment = helpers.addSource(cache, source,
#                    ['mwaa', 'getEnvironment', region, airflowEnv]);
#
#                if (!getEnvironment || getEnvironment.err || !getEnvironment.data || !getEnvironment.data.Environment) {
#                    helpers.addResult(results, 3,
#                        `Unable to get Airflow environment: ${helpers.addError(getEnvironment)}`, region, resource);
#                    return cb();
#                }
#
#                if (getEnvironment.data.Environment.WebserverAccessMode &&
#                    getEnvironment.data.Environment.WebserverAccessMode.toUpperCase() === 'PRIVATE_ONLY') {
#                    helpers.addResult(results, 0,
#                        'Apache Airflow UI can only be accessible from within the VPC',
#                        region, resource);
#                } else {
#                    helpers.addResult(results, 2,
#                        'Apache Airflow UI can be accessed over the internet',
#                        region, resource);
#                }
#                
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }