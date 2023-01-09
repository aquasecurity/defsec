# METADATA
# title :"ECR Repository Tag Immutability"
# description: "Ensures ECR repository image tags cannot be overwritten"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:ECR
#   severity: LOW
#   short_code: ecr-repository-tag-immutability 
#   recommended_action: "Update ECR registry configurations to ensure image tag mutability is set to immutable."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.ecr, function(region, rcb) {
#            var describeRepositories = helpers.addSource(cache, source,
#                ['ecr', 'describeRepositories', region]);
#
#            if (!describeRepositories) return rcb();
#
#            if (describeRepositories.err || !describeRepositories.data) {
#                helpers.addResult(
#                    results, 3,
#                    'Unable to query for ECR repositories: ' + helpers.addError(describeRepositories), region);
#                return rcb();
#            }
#
#            if (describeRepositories.data.length === 0) {
#                helpers.addResult(results, 0, 'No ECR repositories present', region);
#                return rcb();
#            }
#
#            for (var r in describeRepositories.data) {
#                var repository = describeRepositories.data[r];
#                var arn = repository.repositoryArn;
#                var immutability = repository.imageTagMutability;
#
#                if (immutability == 'IMMUTABLE') {
#                    helpers.addResult(results, 0,
#                        'ECR repository mutability setting is set to IMMUTABLE',
#                        region, arn);
#                } else {
#                    helpers.addResult(results, 2,
#                        'ECR repository mutability setting is set to MUTABLE',
#                        region, arn);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }