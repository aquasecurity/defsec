# METADATA
# title :"EKS Latest Platform Version"
# description: "Ensure that EKS clusters are using latest platform version."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service:EKS
#   severity: LOW
#   short_code: eks-latest-platform-version 
#   recommended_action: "Check for the version on all EKS clusters to be the latest platform version."
#   input:
#     selector:
#      - type: cloud
package builtin.aws.rds.aws0180

#function(cache, settings, callback) {
#        var results = [];
#        var source = {};
#        var regions = helpers.regions(settings);
#
#        var acctRegion = helpers.defaultRegion(settings);
#        var awsOrGov = helpers.defaultPartition(settings);
#        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
#
#        var latestVersions = {
#            '1.23': 2,
#            '1.22': 6,
#            '1.21': 11,
#        };
#
#        var deprecatedVersions = {
#            '1.10': '2019-07-22',
#            '1.11': '2019-11-04',
#            '1.12': '2020-05-11',
#            '1.13': '2020-06-30',
#            '1.14': '2020-12-08',
#            '1.15': '2021-05-03',
#            '1.16': '2021-09-27',
#            '1.17': '2021-11-02',
#            '1.18': '2022-03-31',
#            '1.19': '2022-08-01',
#            '1.20': '2022-11-01'
#        };
#
#        async.each(regions.eks, function(region, rcb) {
#            var listClusters = helpers.addSource(cache, source,
#                ['eks', 'listClusters', region]);
#
#            if (!listClusters) return rcb();
#
#            if (listClusters.err || !listClusters.data) {
#                helpers.addResult(
#                    results, 3,
#                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
#                return rcb();
#            }
#
#            if (listClusters.data.length === 0){
#                helpers.addResult(results, 0, 'No EKS clusters present', region);
#                return rcb();
#            }
#
#            for (var c in listClusters.data) {
#                var clusterName = listClusters.data[c];
#                var describeCluster = helpers.addSource(cache, source,
#                    ['eks', 'describeCluster', region, clusterName]);
#
#                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;
#
#                if (!describeCluster || describeCluster.err || !describeCluster.data) {
#                    helpers.addResult(
#                        results, 3,
#                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
#                        region, arn);
#                    continue;
#                }
#
#                if (describeCluster.data.cluster &&
#                    describeCluster.data.cluster.version &&
#                    describeCluster.data.cluster.platformVersion) {
#                    var version = describeCluster.data.cluster.version;
#                    let versionLatestPlatform = (latestVersions[version]) ? latestVersions[version] : null;
#                    
#                    let platform = describeCluster.data.cluster.platformVersion;
#                    let platformVersion = platform.replace('eks.', '');
#
#                    if (versionLatestPlatform) {
#                        if (parseInt(platformVersion) >= versionLatestPlatform) {
#                            helpers.addResult(results, 0,
#                                'EKS cluster is running latest EKS platform version',
#                                region, arn);
#                        } else {
#                            helpers.addResult(results, 2,
#                                'EKS cluster is not running latest EKS platform version',
#                                region, arn);
#                        }
#                    } else if (deprecatedVersions[version]){
#                        helpers.addResult(results, 0,
#                            'EKS cluster using deprecated EKS version',
#                            region, arn);
#                    } else {
#                        helpers.addResult(results, 3, 'EKS cluster is using unknown EKS version', region, arn);
#                    }
#                } else {
#                    helpers.addResult(results, 3, 'Unable to query cluster EKS version or platform version', region, arn);
#                }
#            }
#
#            rcb();
#        }, function() {
#            callback(null, results, source);
#        });
#    }