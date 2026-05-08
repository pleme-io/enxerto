//! JSON-Patch generator — emits the RFC-6902 ops the webhook returns
//! so the apiserver mutates the pod spec in flight.

use serde_json::{Value, json};

use crate::admission::{INJECTED_ANNOTATION, InjectorConfig};

/// Generate the JSON-Patch ops that graft mesh containers + volumes
/// + the idempotency annotation onto a Pod spec. `pod` is the
/// AdmissionReview-supplied pod object (the `request.object`).
#[must_use]
pub fn build_patch(_pod: &Value, cfg: &InjectorConfig) -> Vec<Value> {
    let mut ops: Vec<Value> = Vec::new();

    // 1. Annotation (idempotency marker).
    ops.push(json!({
        "op": "add",
        "path": format!("/metadata/annotations/{}", escape_key(INJECTED_ANNOTATION)),
        "value": "true",
    }));

    // 2. Add the spiffe-csi volume to spec.volumes (use `-` to append).
    ops.push(json!({
        "op": "add",
        "path": "/spec/volumes/-",
        "value": {
            "name": "spiffe-csi",
            "csi": { "driver": cfg.spiffe_csi_driver, "readOnly": true }
        }
    }));

    // 3. Append the iptables-redirect init-container.
    ops.push(json!({
        "op": "add",
        "path": "/spec/initContainers/-",
        "value": iptables_init_container(cfg)
    }));

    // 4. Append the aresta sidecar container.
    ops.push(json!({
        "op": "add",
        "path": "/spec/containers/-",
        "value": aresta_sidecar(cfg)
    }));

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
            // Redirect inbound TCP (anything not destined for loopback) to 15001.
            // Skip the proxy's own UID (1737) so its outbound calls don't loop.
            // Skip ports 22 (ssh), 53 (DNS) so kubelet probes/dns work.
            "iptables -t nat -N ARESTA_INBOUND 2>/dev/null || true; \
             iptables -t nat -F ARESTA_INBOUND; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 22 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -d 127.0.0.0/8 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp -j REDIRECT --to-port {}; \
             iptables -t nat -C PREROUTING -p tcp -j ARESTA_INBOUND 2>/dev/null || \
               iptables -t nat -A PREROUTING -p tcp -j ARESTA_INBOUND; \
             echo 'enxerto: iptables PREROUTING redirect to {} installed'",
            cfg.inbound_port, cfg.inbound_port
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
    fn patch_adds_expected_ops() {
        let pod = json!({"metadata": {"name": "x"}, "spec": {"containers": []}});
        let ops = build_patch(&pod, &InjectorConfig::default());
        assert_eq!(ops.len(), 4);

        // Annotation key escaped.
        let path = ops[0].get("path").unwrap().as_str().unwrap();
        assert!(
            path.starts_with("/metadata/annotations/mesh.pleme.io"),
            "got: {path}"
        );
        // Subsequent ops target /spec/*.
        assert_eq!(ops[1].get("path").unwrap(), "/spec/volumes/-");
        assert_eq!(ops[2].get("path").unwrap(), "/spec/initContainers/-");
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
