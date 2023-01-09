# METADATA
# title :"App Mesh Restrict External Traffic"
# description: "Ensure that Amazon App Mesh virtual nodes have egress only access to other defined resources available within the service mesh."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/app-mesh/latest/userguide/security.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:App Mesh
#   severity: LOW
#   short_code: restrict-external-traffic 
#   recommended_action: "Deny all traffic to the external services"
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        async.each(regions.appmesh, function(region, rcb){        
#            var listMeshes = helpers.addSource(cache, source,
#                ['appmesh', 'listMeshes', region]);
#
#            if (!listMeshes) return rcb();
#
#            if (listMeshes.err || !listMeshes.data) {
#                helpers.addResult(results, 3,
#                    `Unable to query for App Mesh meshes: ${helpers.addError(listMeshes)}`,region);
#                return rcb();
#            }
#
#            if (!listMeshes.data.length) {
#                helpers.addResult(results, 0, 'No App Mesh meshes found', region);
#                return rcb();
#            }
#
#            for (let mesh of listMeshes.data) {
#                if (!mesh.arn) continue;
#
#                let resource = mesh.arn;
#
#                var describeMesh = helpers.addSource(cache, source,
#                    ['appmesh', 'describeMesh', region, mesh.meshName]);
#
#                if (!describeMesh || describeMesh.err || !describeMesh.data ||
#                    !describeMesh.data.mesh) {
#                    helpers.addResult(results, 3,
#                        `Unable to describe App Mesh mesh: ${helpers.addError(describeMesh)}`,
#                        region, resource);
#                    continue;
#                } 
#
#                if (describeMesh.data.mesh.spec &&
#                    describeMesh.data.mesh.spec.egressFilter &&
#                    describeMesh.data.mesh.spec.egressFilter.type.toUpperCase() === 'ALLOW_ALL') {
#                    helpers.addResult(results, 2,
#                        'App Mesh mesh allows access to external services',
#                        region, resource);       
#                } else {
#                    helpers.addResult(results, 0,
#                        'App Mesh mesh does not allow access to external services',
#                        region, resource);
#                }
#            }
#
#            rcb();
#        }, function(){
#            callback(null, results, source);
#        });
#    }