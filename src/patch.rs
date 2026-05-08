//! JSON-Patch generator — emits the RFC-6902 ops the webhook returns
//! so the apiserver mutates the pod spec in flight.

use serde_json::{Value, json};

use crate::admission::{ARESTA_CONFIG_CM_ANNOTATION, INJECTED_ANNOTATION, InjectorConfig};

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
    //
    //    Per-pod override: if the pod carries the
    //    `enxerto.mesh.pleme.io/aresta-config-cm` annotation, the
    //    injector mounts THAT ConfigMap instead of the operator-
    //    configured default. Lets multi-Servico clusters give each
    //    Servico its own aresta config (different peer allow-lists,
    //    different policy defaults, etc.) without bouncing the
    //    injector.
    let aresta_cfg_cm_name = pod
        .pointer(&format!(
            "/metadata/annotations/{}",
            escape_key(ARESTA_CONFIG_CM_ANNOTATION)
        ))
        .and_then(|v| v.as_str())
        .map_or_else(|| cfg.aresta_config_cm.clone(), str::to_string);

    let spiffe_vol = json!({
        "name": "spiffe-csi",
        "csi": { "driver": cfg.spiffe_csi_driver, "readOnly": true }
    });
    let aresta_cfg_vol = json!({
        "name": "aresta-config",
        "configMap": { "name": aresta_cfg_cm_name }
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
            // INBOUND: redirect inbound TCP to aresta-in (15001)
            // unless: ssh/dns/metrics/aresta-self ports, or loopback.
            //
            // OUTBOUND: redirect outbound TCP to aresta-out (15006)
            // unless: traffic from aresta's own UID (1737) — aresta's
            // own dial-out to peers must NOT loop, traffic to
            // loopback / kube-apiserver / DNS, or already destined
            // for aresta-out (15006) / aresta-in (15001).
            "iptables -t nat -N ARESTA_INBOUND 2>/dev/null || true; \
             iptables -t nat -F ARESTA_INBOUND; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 22 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 9090 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport {inbound} -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport {outbound} -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -d 127.0.0.0/8 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp -j REDIRECT --to-port {inbound}; \
             iptables -t nat -C PREROUTING -p tcp -j ARESTA_INBOUND 2>/dev/null || \
               iptables -t nat -A PREROUTING -p tcp -j ARESTA_INBOUND; \
             iptables -t nat -N ARESTA_OUTBOUND 2>/dev/null || true; \
             iptables -t nat -F ARESTA_OUTBOUND; \
             iptables -t nat -A ARESTA_OUTBOUND -m owner --uid-owner {aresta_uid} -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -d 127.0.0.0/8 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p udp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport {inbound} -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport {outbound} -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp -j REDIRECT --to-port {outbound}; \
             iptables -t nat -C OUTPUT -p tcp -j ARESTA_OUTBOUND 2>/dev/null || \
               iptables -t nat -A OUTPUT -p tcp -j ARESTA_OUTBOUND; \
             echo 'enxerto: iptables installed PREROUTING→{inbound}, OUTPUT→{outbound} (skip uid {aresta_uid})'",
            inbound = cfg.inbound_port,
            outbound = 15006,
            aresta_uid = 1737,
        )]
    })
}

fn aresta_sidecar(cfg: &InjectorConfig) -> Value {
    json!({
        "name": "aresta",
        "image": cfg.aresta_image,
        "imagePullPolicy": "IfNotPresent",
        "args": ["--config", "/etc/aresta/config.yaml"],
        // Run as UID 1737 — the iptables OUTPUT chain installed by
        // the init-container has `--uid-owner 1737 -j RETURN`
        // BEFORE the REDIRECT, so aresta's own dial-out to peers
        // doesn't loop back through itself.
        "securityContext": {
            "runAsUser": 1737,
            "runAsNonRoot": true
        },
        "ports": [
            { "name": "mesh-inbound", "containerPort": cfg.inbound_port, "protocol": "TCP" },
            { "name": "mesh-outbound", "containerPort": 15006, "protocol": "TCP" },
            { "name": "mesh-metrics", "containerPort": 9090, "protocol": "TCP" }
        ],
        "volumeMounts": [
            {
                "name": "spiffe-csi",
                "mountPath": "/run/spiffe.io",
                "readOnly": true
            },
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

    #[test]
    fn aresta_config_cm_annotation_overrides_default() {
        let pod = json!({
            "metadata": {
                "name": "x",
                "annotations": {
                    "enxerto.mesh.pleme.io/aresta-config-cm": "per-pod-config"
                }
            },
            "spec": { "containers": [{"name":"main"}] }
        });
        let ops = build_patch(&pod, &InjectorConfig::default());
        // ops[1] is the volumes-full-array add (annotation mut means
        // /spec/volumes is absent). Find the aresta-config volume
        // inside that array and check its CM name.
        let vols = ops[1].get("value").unwrap().as_array().unwrap();
        let aresta_cfg = vols
            .iter()
            .find(|v| v.get("name").unwrap() == "aresta-config")
            .expect("aresta-config volume present");
        assert_eq!(
            aresta_cfg.pointer("/configMap/name").unwrap().as_str().unwrap(),
            "per-pod-config",
            "annotation must override the default"
        );
    }
}
