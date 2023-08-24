package appshield.kubernetes.KSV122

# Test case for a RoleBinding with anonymous/unauthenticated user binding
test_role_binding_with_anonymous_user_binding {
    r := deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": "anonymous_user",
            "namespace": "default",
        },
        "subjects": [{
            "kind": "User",
            "name": "system:unauthenticated",
            "apiGroup": "rbac.authorization.k8s.io",
        },
        {
            "kind": "User",
            "name": "system:anonymous",
            "apiGroup": "rbac.authorization.k8s.io",
        }],
        "roleRef": {
            "kind": "Role",
            "name": "role",
            "apiGroup": "rbac.authorization.k8s.io",
        },
    }

	count(r) == 1
}

#Test case for a ClusterRoleBinding with anonymous/unauthenticated user binding
test_cluster_role_binding_with_anonymous_user_binding {
    r := deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRolebinding",
        "metadata": {
            "name": "anonymous_user",
            "namespace": "default",
        },
        "subjects": [{
            "kind": "User",
            "name": "system:unauthenticated",
            "apiGroup": "rbac.authorization.k8s.io",
        },
        {
            "kind": "User",
            "name": "system:anonymous",
            "apiGroup": "rbac.authorization.k8s.io",
        }],
        "roleRef": {
            "kind": "ClusterRole",
            "name": "clusterrole",
            "apiGroup": "rbac.authorization.k8s.io",
        },
    }

	count(r) == 1
}

# Test case for a RoleBinding with non-anonymous user binding
test_role_binding_with_non_anonymous_user_binding {
    r := deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "name": "non_anonymous_user",
            "namespace": "default",
        },
        "subjects": {
            "kind": "User",
            "name": "system:authenticated",
            "apiGroup": "rbac.authorization.k8s.io",
        },
        "roleRef": {
            "kind": "Role",
            "name": "role",
            "apiGroup": "rbac.authorization.k8s.io",
        },
    }

	count(r) == 0
}

# Test case for a ClusterRoleBinding with non-anonymous user binding
test_cluster_role_binding_with_non_anonymous_user_binding {
    r := deny with input as {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": "non_anonymous_user",
            "namespace": "default",
        },
        "subjects": {
            "kind": "User",
            "name": "system:authenticated",
            "apiGroup": "rbac.authorization.k8s.io",
        },
        "roleRef": {
            "kind": "ClusterRole",
            "name": "clusterrole",
            "apiGroup": "rbac.authorization.k8s.io",
        },
    }

	count(r) == 0
}