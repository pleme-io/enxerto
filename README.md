# enxerto

`enxerto` (Brazilian-Portuguese: *graft*) — pleme-io mesh
sidecar-injector. A Kubernetes
`MutatingAdmissionWebhook` that grafts the
[`aresta`](https://github.com/pleme-io/aresta) proxy + an iptables
init-container onto Pods labeled for mesh injection.

Sprint **M2.2** of [`pleme-io/theory/MESH-EXECUTION-PLAN.md`](https://github.com/pleme-io/theory/blob/main/MESH-EXECUTION-PLAN.md).

## Selection

A pod is injected iff:

- it has label `mesh.pleme.io/inject=true` (per-pod opt-in), **OR**
- its namespace has label `mesh.pleme.io/inject=true` (per-ns opt-in)

AND it does NOT carry the annotation `mesh.pleme.io/injected=true`
(idempotency — re-admission is a no-op).

## What gets grafted

1. **Init-container** running `iptables` to redirect inbound TCP
   traffic to `127.0.0.1:15001` (the proxy).
2. **`aresta` sidecar container** sharing the SPIFFE Workload API
   socket via a `csi.spiffe.io` CSI volume.
3. The annotation `mesh.pleme.io/injected=true` so re-admission is a
   no-op.

## Deploy

```yaml
# MutatingWebhookConfiguration that points apiserver → enxerto
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata: { name: enxerto }
webhooks:
  - name: enxerto.mesh.pleme.io
    clientConfig:
      service:
        namespace: mesh-system
        name: enxerto
        path: /mutate
        port: 8443
      caBundle: <base64 PEM>
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
    objectSelector:
      matchLabels:
        mesh.pleme.io/inject: "true"
    sideEffects: None
    admissionReviewVersions: ["v1"]
```

## License

Dual MIT OR Apache-2.0.
