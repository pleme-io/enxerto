//! JSON-Patch generator — emits the RFC-6902 ops the webhook returns
//! so the apiserver mutates the pod spec in flight.

use serde_json::{Value, json};

use crate::admission::{INJECTED_ANNOTATION, InjectorConfig};

/// Generate the JSON-Patch ops that graft mesh containers + volumes
/// + the idempotency annotation onto a Pod spec. `pod` is the
/// AdmissionReview-supplied pod object (the `request.object`).
///
/// JSON-Patch `add /path/-` only appends to an *existing* array. If
/// the pod has no `volumes` / `initContainers` / `annotations`, those
/// paths don't exist yet — `/-` fails with "doc is missing path".
/// The fix: detect missing fields and emit a full-array (or empty-
/// object) `add` for them first.
#[must_use]
pub fn build_patch(pod: &Value, cfg: &InjectorConfig) -> Vec<Value> {
    let mut ops: Vec<Value> = Vec::new();

    // 1. Annotation. /metadata/annotations may not exist on minimal
    //    pods; if missing, create the whole map at once.
    if pod.pointer("/metadata/annotations").is_none() {
        ops.push(json!({
            "op": "add",
            "path": "/metadata/annotations",
            "value": { INJECTED_ANNOTATION: "true" }
        }));
    } else {
        ops.push(json!({
            "op": "add",
            "path": format!("/metadata/annotations/{}", escape_key(INJECTED_ANNOTATION)),
            "value": "true",
        }));
    }

    // 2. Volumes — spiffe-csi + aresta-config (ConfigMap mount).
    //    Append to /spec/volumes (creating the array if absent).
    let spiffe_vol = json!({
        "name": "spiffe-csi",
        "csi": { "driver": cfg.spiffe_csi_driver, "readOnly": true }
    });
    let aresta_cfg_vol = json!({
        "name": "aresta-config",
        "configMap": { "name": cfg.aresta_config_cm }
    });
    if pod.pointer("/spec/volumes").is_none() {
        ops.push(json!({
            "op": "add",
            "path": "/spec/volumes",
            "value": [spiffe_vol, aresta_cfg_vol]
        }));
    } else {
        ops.push(json!({ "op": "add", "path": "/spec/volumes/-", "value": spiffe_vol }));
        ops.push(json!({ "op": "add", "path": "/spec/volumes/-", "value": aresta_cfg_vol }));
    }

    // 3. iptables-redirect init-container → /spec/initContainers.
    let init = iptables_init_container(cfg);
    if pod.pointer("/spec/initContainers").is_none() {
        ops.push(json!({ "op": "add", "path": "/spec/initContainers", "value": [init] }));
    } else {
        ops.push(json!({ "op": "add", "path": "/spec/initContainers/-", "value": init }));
    }

    // 4. aresta sidecar → /spec/containers (always exists; pods are
    //    validated to have ≥1 container).
    ops.push(json!({
        "op": "add",
        "path": "/spec/containers/-",
        "value": aresta_sidecar(cfg)
    }));

    // 5. imagePullSecrets — ensure the configured Secrets are present
    //    so the aresta sidecar can pull from ghcr. Append-or-create.
    if !cfg.image_pull_secrets.is_empty() {
        let secrets: Vec<Value> = cfg
            .image_pull_secrets
            .iter()
            .map(|s| json!({ "name": s }))
            .collect();
        if pod.pointer("/spec/imagePullSecrets").is_none() {
            ops.push(json!({
                "op": "add",
                "path": "/spec/imagePullSecrets",
                "value": secrets
            }));
        } else {
            for s in secrets {
                ops.push(json!({
                    "op": "add",
                    "path": "/spec/imagePullSecrets/-",
                    "value": s
                }));
            }
        }
    }

    ops
}

fn iptables_init_container(cfg: &InjectorConfig) -> Value {
    json!({
        "name": "enxerto-iptables-init",
        "image": cfg.iptables_image,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "capabilities": { "add": ["NET_ADMIN", "NET_RAW"] },
            "runAsUser": 0,
            "runAsNonRoot": false,
            "allowPrivilegeEscalation": true,
        },
        "command": ["/bin/sh", "-c"],
        "args": [format!(
            // Redirect inbound TCP to 15001 (aresta inbound) UNLESS:
            //  - destined for the proxy's own metrics/health ports
            //  - destined for the iptables-skip ports (22 ssh, 53 dns)
            //  - destined for loopback (127.0.0.0/8) — pod-internal IPC
            //
            // We skip 9090 (aresta prometheus) so kubelet probes hit
            // plaintext HTTP, not the mTLS-only inbound listener.
            "iptables -t nat -N ARESTA_INBOUND 2>/dev/null || true; \
             iptables -t nat -F ARESTA_INBOUND; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 22 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 9090 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport {} -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -d 127.0.0.0/8 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp -j REDIRECT --to-port {}; \
             iptables -t nat -C PREROUTING -p tcp -j ARESTA_INBOUND 2>/dev/null || \
               iptables -t nat -A PREROUTING -p tcp -j ARESTA_INBOUND; \
             echo 'enxerto: iptables PREROUTING redirect to {} installed'",
            cfg.inbound_port, cfg.inbound_port, cfg.inbound_port
        )]
    })
}

fn aresta_sidecar(cfg: &InjectorConfig) -> Value {
    json!({
        "name": "aresta",
        "image": cfg.aresta_image,
        "imagePullPolicy": "IfNotPresent",
        "args": ["--config", "/etc/aresta/config.yaml"],
        "ports": [
            { "name": "mesh-inbound", "containerPort": cfg.inbound_port, "protocol": "TCP" },
            { "name": "mesh-metrics", "containerPort": 9090, "protocol": "TCP" }
        ],
        "volumeMounts": [
            {
                "name": "spiffe-csi",
                "mountPath": "/run/spiffe.io",
                "readOnly": true
            },
            // Config materialized via a separate ConfigMap that lives
            // alongside the pod (M4 renderer emits it; for now the
            // operator drops `aresta-config` ConfigMap by hand).
            {
                "name": "aresta-config",
                "mountPath": "/etc/aresta",
                "readOnly": true
            }
        ],
        "readinessProbe": {
            "httpGet": { "path": "/metrics", "port": 9090 },
            "initialDelaySeconds": 1,
            "periodSeconds": 5
        },
        "resources": {
            "requests": { "cpu": "20m", "memory": "32Mi" },
            "limits":   { "cpu": "200m", "memory": "128Mi" }
        }
    })
}

/// JSON-Pointer escape (RFC 6901): `~` -> `~0`, `/` -> `~1`.
fn escape_key(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_appends_when_arrays_already_exist() {
        let pod = json!({
            "metadata": { "name": "x", "annotations": { "x": "y" } },
            "spec": {
                "containers": [{"name": "main"}],
                "initContainers": [{"name": "old-init"}],
                "volumes": [{"name": "data"}]
            }
        });
        let ops = build_patch(&pod, &InjectorConfig::default());
        // 1 annotation + 2 volumes + 1 init + 1 container + 1 imagePullSecrets-array = 6
        assert_eq!(ops.len(), 6);
        assert!(ops[0].get("path").unwrap().as_str().unwrap()
            .starts_with("/metadata/annotations/mesh.pleme.io"));
        assert_eq!(ops[1].get("path").unwrap(), "/spec/volumes/-");
        assert_eq!(ops[2].get("path").unwrap(), "/spec/volumes/-");
        assert_eq!(ops[3].get("path").unwrap(), "/spec/initContainers/-");
        assert_eq!(ops[4].get("path").unwrap(), "/spec/containers/-");
    }

    #[test]
    fn patch_handles_missing_arrays() {
        // Minimal pod — no annotations, no volumes, no initContainers.
        let pod = json!({"metadata": {"name": "x"}, "spec": {"containers": [{"name":"main"}]}});
        let ops = build_patch(&pod, &InjectorConfig::default());
        // 1 annotation + 1 volumes-full-array + 1 init-full-array
        // + 1 container + 1 imagePullSecrets-array = 5
        assert_eq!(ops.len(), 5);

        // Annotation: full-map add.
        assert_eq!(ops[0].get("path").unwrap(), "/metadata/annotations");
        assert!(ops[0].pointer("/value/mesh.pleme.io~1injected").is_some());

        // Volumes: full-array add carrying both spiffe-csi + aresta-config.
        assert_eq!(ops[1].get("path").unwrap(), "/spec/volumes");
        let vols = ops[1].get("value").unwrap().as_array().unwrap();
        assert_eq!(vols.len(), 2);
        assert!(vols.iter().any(|v| v.get("name").unwrap() == "spiffe-csi"));
        assert!(vols.iter().any(|v| v.get("name").unwrap() == "aresta-config"));

        // initContainers: full-array add.
        assert_eq!(ops[2].get("path").unwrap(), "/spec/initContainers");
        assert!(ops[2].get("value").unwrap().is_array());

        // containers: append (always exists).
        assert_eq!(ops[3].get("path").unwrap(), "/spec/containers/-");
    }

    #[test]
    fn iptables_init_has_net_admin() {
        let cfg = InjectorConfig::default();
        let init = iptables_init_container(&cfg);
        let caps = init
            .pointer("/securityContext/capabilities/add")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(
            caps.iter()
                .any(|v| v.as_str() == Some("NET_ADMIN"))
        );
    }

    #[test]
    fn json_pointer_escapes_slashes() {
        assert_eq!(escape_key("mesh.pleme.io/injected"), "mesh.pleme.io~1injected");
        assert_eq!(escape_key("a~b"), "a~0b");
    }
}
