package lib.kubernetes

test_pod {
	# spec
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-pod",
		}]},
	}

	test_pods[_].spec.containers[_].name == "hello-pod"
}

test_cron_job {
	# spec -> jobTemplate -> spec -> template -> spec
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "CronJob",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {
			"restartPolicy": "OnFailure",
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello !' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello-cron-job",
			}],
		}}}}},
	}

	test_pods[_].spec.containers[_].name == "hello-cron-job"
}

test_deployment {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Deployment",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-deployment",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-deployment"
}

test_stateful_set {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "StatefulSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-stateful-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-stateful-set"
}

test_daemon_set {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "DaemonSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-daemon-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-daemon-set"
}

test_replica_set {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "ReplicaSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-replica-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-replica-set"
}

test_replication_controller {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "ReplicationController",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-replication-controller",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-replication-controller"
}

test_job {
	# spec -> template
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Job",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-job",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-job"
}

test_init_containers {
	test_containers := containers with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"initContainers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-init-containers",
		}]},
	}

	test_containers[_].name == "hello-init-containers"
}

test_containers {
	test_containers := containers with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-containers",
		}]},
	}

	test_containers[_].name == "hello-containers"
}

test_isapiserver_has_valid_container {
	apiserver_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-apiserver",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["kube-apiserver-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/kube-apiserver",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-kube-apiserver"],
				"name": "invalid-2",
			},
			{
				"command": [
					"kube-apiserver",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}

	is_apiserver(apiserver_container)
	any([apiserver_container.name == "valid-1", apiserver_container.name == "valid-2"])
}

test_isapiserver_has_not_valid_container {
	apiserver_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-apiserver",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-kube-apiserver",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["kube-apiserver-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["kube-apiserver-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_apiserver(apiserver_container)
}

test_etcd_has_valid_container {
	etcd_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["etcd-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/etcd",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-etcd"],
				"name": "invalid-2",
			},
			{
				"command": [
					"etcd",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}
	is_etcd(etcd_container)
	any([etcd_container.name == "valid-1", etcd_container.name == "valid-2"])
}

test_etcd_has_not_valid_container {
	etcd_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-etcd",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["etcd-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["etcd-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_etcd(etcd_container)
}

test_controllermananager_has_valid_container {
	controllermananager_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-controller-manager",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["kube-controller-manager-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/kube-controller-manager",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-kube-controller-manager"],
				"name": "invalid-2",
			},
			{
				"command": [
					"kube-controller-manager",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}
	is_controllermananager(controllermananager_container)
	any([controllermananager_container.name == "valid-1", controllermananager_container.name == "valid-2"])
}

test_controllermananager_has_not_valid_container {
	controllermananager_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-controller-manager",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-kube-controller-manager",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["kube-controller-manager-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["kube-controller-manager-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_controllermananager(controllermananager_container)
}

test_scheduler_has_valid_container {
	scheduler_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-scheduler",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": ["kube-scheduler-invalid"],
				"name": "invalid-1",
			},
			{
				"command": [
					"/usr/bin/kube-scheduler",
					"--test-flag=test",
				],
				"name": "valid-1",
			},
			{
				"command": ["invalid-kube-scheduler"],
				"name": "invalid-2",
			},
			{
				"command": [
					"kube-scheduler",
					"--test-flag=test",
				],
				"name": "valid-2",
			},
		]},
	}
	is_scheduler(scheduler_container)
	any([scheduler_container.name == "valid-1", scheduler_container.name == "valid-2"])
}

test_scheduler_has_not_valid_container {
	scheduler_container := containers[_] with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "kube-scheduler",
			"namespace": "kube-system",
		},
		"spec": {"containers": [
			{
				"command": [
					"/usr/bin-kube-scheduler",
					"--test-flag=test",
				],
				"name": "invalid-1",
			},
			{
				"command": ["kube-scheduler-invalid"],
				"name": "invalid-2",
			},
			{
				"command": ["kube-scheduler-invalid"],
				"name": "invalid-3",
			},
		]},
	}
	not is_scheduler(scheduler_container)
}
