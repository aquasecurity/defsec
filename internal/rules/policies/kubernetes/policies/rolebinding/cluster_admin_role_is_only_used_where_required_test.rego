package builtin.kubernetes.KSV111

test_cluster_role_admin__used_with_non_system_role_binding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "RoleBinding",
		"metadata": {
			"name": "ystem:read-pods",
			"namespace": "default",
		},
		"subjects": [{
			"kind": "User",
			"name": "jane",
			"apiGroup": "rbac.authorization.k8s.io",
		}],
		"roleRef": {
			"kind": "Role",
			"name": "cluster-admin",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 1
}

 
test_no_cluster_role_admin_is_used {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "RoleBinding",
		"metadata": {
			"name": "system:read-pods",
			"namespace": "default",
		},
		"subjects": [{
			"kind": "User",
			"name": "jane",
			"apiGroup": "rbac.authorization.k8s.io",
		}],
		"roleRef": {
			"kind": "Role",
			"name": "clusteradmin",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 0
}

test_cluster_role_admin__used_with_system_role_binding {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "ClusterRoleBinding",
		"metadata": {
			"name": "system:read-pods",
			"namespace": "default",
		},
		"subjects": [{
			"kind": "User",
			"name": "jane",
			"apiGroup": "rbac.authorization.k8s.io",
		}],
		"roleRef": {
			"kind": "Role",
			"name": "cluster-admin",
			"apiGroup": "rbac.authorization.k8s.io",
		},
	}

	count(r) == 0
}