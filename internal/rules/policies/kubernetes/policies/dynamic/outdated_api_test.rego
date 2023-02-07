package defsec.kubernetes.KSV107

recommendedVersions_mock_data = {"batch/v1": {"Job": {
	"deprecation_version": "v1.21",
	"replacement_version": "batch.v1.CronJobList",
	"removed_version": "v1.25",
	"ref": "https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api/batch/v1beta1/zz_generated.prerelease-lifecycle.go",
}}}

test_eval_k8s_api_with_data_match {
	r := deny with input as {
		"apiVersion": "batch/v1",
		"kind": "Job",
		"metadata": {"name": "pi"},
		"spec": {
			"template": {"spec": {
				"containers": [{
					"name": "pi",
					"image": "perl:5.34.0",
					"command": [
						"perl",
						"-Mbignum=bpi",
						"-wle",
						"print bpi(2000)",
					],
				}],
				"restartPolicy": "Never",
			}},
			"backoffLimit": 4,
		},
	}
		with recommendedVersions as recommendedVersions_mock_data

	count(r) > 0
}

test_eval_k8s_api_with_data_do_not_match {
	r := deny with input as {
		"apiVersion": "batch/v2",
		"kind": "Job",
		"metadata": {"name": "pi"},
		"spec": {
			"template": {"spec": {
				"containers": [{
					"name": "pi",
					"image": "perl:5.34.0",
					"command": [
						"perl",
						"-Mbignum=bpi",
						"-wle",
						"print bpi(2000)",
					],
				}],
				"restartPolicy": "Never",
			}},
			"backoffLimit": 4,
		},
	}
		with recommendedVersions as recommendedVersions_mock_data

	count(r) == 0
}
