permit (
    principal,
    action == Kubernetes::Action::"describe",
    resource
)
when {
    principal in Kubernetes::Role::"viewer" ||
    principal in Kubernetes::Role::"admin"
};

permit (
    principal,
    action == Kubernetes::Action::"delete",
    resource
)
when {
    principal in Kubernetes::Role::"admin"
};
