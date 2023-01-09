# METADATA
# title :"CodeStar Valid Repository Providers"
# description: "Ensure that CodeStar projects are not using undesired repository providers."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/codestar/latest/userguide/getting-started.html#getting-started-create
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:CodeStar
#   severity: LOW
#   short_code: codestar-valid-repo-providers 
#   recommended_action: "Ensure diallowed repository providers are not being used for CodeStar projects"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var config = {
#            codestar_disallowed_repo_providers: settings.codestar_disallowed_repo_providers || this.settings.codestar_disallowed_repo_providers.default
#        };
#
#        if (!config.codestar_disallowed_repo_providers.length) return callback(null, results, source);
#
#        async.each(regions.codestar, function(region, rcb){
#            var listProjects = helpers.addSource(cache, source, ['codestar', 'listProjects', region]);
#
#            if (!listProjects) return rcb();
#
#            if (listProjects.err || !listProjects.data) {
#                helpers.addResult(results, 3, `Unable to query CodeStar projects: ${helpers.addError(listProjects)}`, region);
#                return rcb();
#            }
#
#            if (!listProjects.data.length) {
#                helpers.addResult(results, 0, 'No CodeStar projects found', region);
#                return rcb();
#            }
#
#            async.each(listProjects.data, function(project, cb) {
#                if (!project.projectId) return cb();
#
#                var describeProject = helpers.addSource(cache, source, ['codestar', 'describeProject', region, project.projectId]);
#
#                if (!describeProject || describeProject.err || !describeProject.data || !describeProject.data.projectTemplateId) {
#                    helpers.addResult(results, 3,
#                        `Unable to query CodeStar project: ${helpers.addError(describeProject)}`, region, project.projectId);
#                    return cb();
#                }
#
#                let repoProvider = (describeProject.data.projectTemplateId.split('/').length > 1) ?
#                    describeProject.data.projectTemplateId.split('/')[1] : '';
#                
#                if (config.codestar_disallowed_repo_providers.includes(repoProvider)) {
#                    helpers.addResult(results, 2,
#                        `CodeStar project is using ${repoProvider} as repository provider which should not be used`,
#                        region, project.projectArn);
#                } else {
#                    helpers.addResult(results, 0,
#                        `CodeStar project is using ${repoProvider} as repository provider`,
#                        region, project.projectArn);
#                }
#                cb();
#            }, function(){
#                rcb();
#            });
#        }, function(){
#            callback(null, results, source);
#        });
#    }