//! JSON-Patch generator — emits the RFC-6902 ops the webhook returns
//! so the apiserver mutates the pod spec in flight.

use serde_json::{Value, json};

use crate::admission::{
    ARESTA_CONFIG_CM_ANNOTATION, INJECTED_ANNOTATION, InjectorConfig, SKIP_INBOUND_PORTS_ANNOTATION,
};

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

    // 2. Volumes — spiffe-csi + aresta-config. IDEMPOTENT: skip a
    //    volume if a same-name volume already exists on the pod
    //    (chart-emitted templates may have wired spiffe-csi for
    //    pre-mesh experiments; duplicate names invalidate the Pod).
    let aresta_cfg_cm_name = pod
        .pointer(&format!(
            "/metadata/annotations/{}",
            escape_key(ARESTA_CONFIG_CM_ANNOTATION)
        ))
        .and_then(|v| v.as_str())
        .map_or_else(|| cfg.aresta_config_cm.clone(), str::to_string);

    let existing_volumes: std::collections::HashSet<String> = pod
        .pointer("/spec/volumes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut new_volumes: Vec<Value> = Vec::new();
    if !existing_volumes.contains("spiffe-csi") {
        new_volumes.push(json!({
            "name": "spiffe-csi",
            "csi": { "driver": cfg.spiffe_csi_driver, "readOnly": true }
        }));
    }
    if !existing_volumes.contains("aresta-config") {
        new_volumes.push(json!({
            "name": "aresta-config",
            "configMap": { "name": aresta_cfg_cm_name }
        }));
    }

    if pod.pointer("/spec/volumes").is_none() && !new_volumes.is_empty() {
        ops.push(json!({
            "op": "add",
            "path": "/spec/volumes",
            "value": new_volumes
        }));
    } else {
        for v in new_volumes {
            ops.push(json!({ "op": "add", "path": "/spec/volumes/-", "value": v }));
        }
    }

    // 3. iptables-redirect init-container → /spec/initContainers.
    let skip_ports = pod
        .pointer(&format!(
            "/metadata/annotations/{}",
            escape_key(SKIP_INBOUND_PORTS_ANNOTATION)
        ))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let init = iptables_init_container(cfg, skip_ports.as_deref());
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

    // 6. Probe rewrite — kubelet's livenessProbe + readinessProbe on
    //    each workload container originally hit the workload's port
    //    directly. With the aresta sidecar in place, those ports get
    //    REDIRECTed by iptables PREROUTING into aresta-in's mTLS-only
    //    listener — the kubelet's plaintext probe fails, the pod
    //    CrashLoopBackOff'd. Rewriting both probes to the aresta
    //    proxy's plain-HTTP probe port (4191) lets kubelet through
    //    while leaving the workload port REDIRECTed for real peer
    //    mTLS traffic.
    //
    //    What we rewrite:
    //      - httpGet probes: replace `port` with the proxy probe
    //        port, replace `path` with "/ready" (liveness) or "/live"
    //        (also "/ready" for the readiness probe).
    //
    //    What we leave alone:
    //      - tcpSocket / grpc / exec probes — these don't translate
    //        to a plain-HTTP /live, /ready endpoint shape. Rare in
    //        the openclaw fleet; revisit when an actual case arrives.
    //      - startupProbe — usually wants the workload's actual
    //        startup signal; aresta's /ready isn't a substitute.
    if let Some(containers) = pod.pointer("/spec/containers").and_then(|v| v.as_array()) {
        for (idx, container) in containers.iter().enumerate() {
            for (probe, target_path) in
                [("livenessProbe", "/live"), ("readinessProbe", "/ready")]
            {
                if let Some(httpget) = container.pointer(&format!("/{probe}/httpGet")) {
                    // Only rewrite httpGet probes (skip tcpSocket /
                    // grpc / exec).
                    if httpget.is_object() {
                        // Use the literal port number 4191 (NOT the
                        // "mesh-probe" name) — K8s probe named-port
                        // resolution is scoped to the container's own
                        // portList, and the workload container has no
                        // mesh-probe port. The aresta sidecar binds
                        // 4191 in the pod network namespace, so it's
                        // reachable via the pod IP.
                        ops.push(json!({
                            "op": "replace",
                            "path": format!("/spec/containers/{idx}/{probe}/httpGet/port"),
                            "value": 4191
                        }));
                        ops.push(json!({
                            "op": "replace",
                            "path": format!("/spec/containers/{idx}/{probe}/httpGet/path"),
                            "value": target_path
                        }));
                        // Force scheme to HTTP — workload may have
                        // been HTTPS but aresta's probe is plain.
                        if httpget.get("scheme").is_some() {
                            ops.push(json!({
                                "op": "replace",
                                "path": format!("/spec/containers/{idx}/{probe}/httpGet/scheme"),
                                "value": "HTTP"
                            }));
                        }
                    }
                }
            }
        }
    }

    ops
}

fn iptables_init_container(cfg: &InjectorConfig, skip_inbound_ports: Option<&str>) -> Value {
    // Build extra RETURN rules for ports the workload speaks
    // plaintext on (kubelet probes hit the workload directly).
    let extra_skip_lines: String = skip_inbound_ports
        .unwrap_or("")
        .split(',')
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .map(|p| {
            format!(
                "iptables -t nat -A ARESTA_INBOUND -p tcp --dport {p} -j RETURN; \
                 iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport {p} -j RETURN; "
            )
        })
        .collect();

    // Outbound REDIRECT shape:
    //  - empty mesh_outbound_cidrs (back-compat): one catch-all
    //    REDIRECT for all TCP not already RETURNed.
    //  - non-empty: per-CIDR REDIRECTs only; non-mesh egress
    //    (cloudflared → CF edge, workloads → public APIs) falls
    //    through and is passed unchanged.
    let outbound_redirect_lines: String = if cfg.mesh_outbound_cidrs.is_empty() {
        format!(
            "iptables -t nat -A ARESTA_OUTBOUND -p tcp -j REDIRECT --to-port {outbound}; ",
            outbound = 15006
        )
    } else {
        cfg.mesh_outbound_cidrs
            .iter()
            .map(|cidr| {
                format!(
                    "iptables -t nat -A ARESTA_OUTBOUND -p tcp -d {cidr} -j REDIRECT --to-port {outbound}; ",
                    outbound = 15006
                )
            })
            .collect()
    };
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
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport 4191 -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport {inbound} -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -p tcp --dport {outbound_port} -j RETURN; \
             iptables -t nat -A ARESTA_INBOUND -d 127.0.0.0/8 -j RETURN; \
             iptables -t nat -N ARESTA_OUTBOUND 2>/dev/null || true; \
             iptables -t nat -F ARESTA_OUTBOUND; \
             iptables -t nat -A ARESTA_OUTBOUND -m owner --uid-owner {aresta_uid} -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -d 127.0.0.0/8 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p udp --dport 53 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport 443 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport 6443 -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport {inbound} -j RETURN; \
             iptables -t nat -A ARESTA_OUTBOUND -p tcp --dport {outbound_port} -j RETURN; \
             {extra_skip}\
             iptables -t nat -A ARESTA_INBOUND -p tcp -j REDIRECT --to-port {inbound}; \
             iptables -t nat -C PREROUTING -p tcp -j ARESTA_INBOUND 2>/dev/null || \
               iptables -t nat -A PREROUTING -p tcp -j ARESTA_INBOUND; \
             {outbound_redirect}\
             iptables -t nat -C OUTPUT -p tcp -j ARESTA_OUTBOUND 2>/dev/null || \
               iptables -t nat -A OUTPUT -p tcp -j ARESTA_OUTBOUND; \
             echo 'enxerto: iptables installed PREROUTING→{inbound}, OUTPUT→{outbound_port} (skip uid {aresta_uid})'",
            inbound = cfg.inbound_port,
            outbound_port = 15006,
            aresta_uid = 1737,
            extra_skip = extra_skip_lines,
            outbound_redirect = outbound_redirect_lines,
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
            { "name": "mesh-metrics", "containerPort": 9090, "protocol": "TCP" },
            // Plain-HTTP probe-port — kubelet hits /live + /ready
            // here. Workload's livenessProbe + readinessProbe are
            // rewritten by the patcher to point at this named port,
            // so kubelet doesn't go through the iptables PREROUTING
            // REDIRECT into the mTLS-only inbound listener.
            { "name": "mesh-probe", "containerPort": 4191, "protocol": "TCP" }
        ],
        // Aresta itself reports liveness on its probe port — so even
        // before SVID acquisition (probe /ready returns 503), kubelet
        // sees the proxy as alive (probe /live = 200) and doesn't
        // restart it during the SPIRE-registration window.
        "livenessProbe": {
            "httpGet": { "path": "/live", "port": "mesh-probe" },
            "initialDelaySeconds": 2,
            "periodSeconds": 30
        },
        "readinessProbe": {
            "httpGet": { "path": "/ready", "port": "mesh-probe" },
            "initialDelaySeconds": 2,
            "periodSeconds": 5
        },
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
        "resources": {
            // Tight CPU req — pleme-dev's single-node cluster runs N
            // Servicos × aresta sidecar; default 20m × 7 sidecars
            // exhausted node CPU. 5m is enough for proxy idle + the
            // occasional handshake; bursts are absorbed by the limit.
            "requests": { "cpu": "5m",  "memory": "32Mi" },
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
        let init = iptables_init_container(&cfg, None);
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
    fn empty_mesh_cidrs_yields_catch_all_outbound_redirect() {
        let cfg = InjectorConfig::default();
        let init = iptables_init_container(&cfg, None);
        let args = init.pointer("/args/0").unwrap().as_str().unwrap();
        // Catch-all REDIRECT for ALL outbound TCP (back-compat).
        assert!(
            args.contains("ARESTA_OUTBOUND -p tcp -j REDIRECT --to-port 15006"),
            "back-compat: empty mesh_outbound_cidrs must REDIRECT all outbound TCP. got args:\n{args}"
        );
        // Must NOT contain a per-CIDR REDIRECT.
        assert!(
            !args.contains("-d 10.42.0.0/16 -j REDIRECT"),
            "must NOT use per-CIDR REDIRECT when mesh_outbound_cidrs is empty"
        );
    }

    #[test]
    fn probe_httpget_rewritten_to_mesh_probe_port() {
        let pod = json!({
            "metadata": {"name": "x"},
            "spec": {
                "containers": [{
                    "name": "main",
                    "livenessProbe": {
                        "httpGet": { "path": "/healthz", "port": 8082 }
                    },
                    "readinessProbe": {
                        "httpGet": { "path": "/healthz", "port": 8082 }
                    }
                }]
            }
        });
        let ops = build_patch(&pod, &InjectorConfig::default());
        // Locate the four replace ops (one path + one port per probe).
        let replaces: Vec<_> = ops
            .iter()
            .filter(|op| op.get("op").and_then(|v| v.as_str()) == Some("replace"))
            .collect();
        assert!(
            replaces.len() >= 4,
            "expect at least 2 path + 2 port replacements; got {} ops:\n{:#?}",
            replaces.len(),
            replaces
        );
        // Liveness probe rewritten to /live + mesh-probe.
        assert!(
            replaces.iter().any(|op| op.get("path").unwrap()
                == "/spec/containers/0/livenessProbe/httpGet/port"
                && op.get("value").unwrap() == 4191)
        );
        assert!(
            replaces.iter().any(|op| op.get("path").unwrap()
                == "/spec/containers/0/livenessProbe/httpGet/path"
                && op.get("value").unwrap() == "/live")
        );
        // Readiness probe rewritten to /ready + mesh-probe.
        assert!(
            replaces.iter().any(|op| op.get("path").unwrap()
                == "/spec/containers/0/readinessProbe/httpGet/port"
                && op.get("value").unwrap() == 4191)
        );
        assert!(
            replaces.iter().any(|op| op.get("path").unwrap()
                == "/spec/containers/0/readinessProbe/httpGet/path"
                && op.get("value").unwrap() == "/ready")
        );
    }

    #[test]
    fn probe_rewrite_skips_tcp_socket_probes() {
        let pod = json!({
            "metadata": {"name": "x"},
            "spec": {
                "containers": [{
                    "name": "main",
                    "livenessProbe": {
                        "tcpSocket": { "port": 8082 }
                    }
                }]
            }
        });
        let ops = build_patch(&pod, &InjectorConfig::default());
        // No replace ops should target livenessProbe.
        assert!(
            !ops.iter().any(|op| op
                .get("path")
                .and_then(|v| v.as_str())
                .map_or(false, |p| p.contains("livenessProbe"))),
            "tcpSocket probes must not be rewritten — got ops {:#?}",
            ops
        );
    }

    #[test]
    fn probe_rewrite_skips_grpc_probes() {
        let pod = json!({
            "metadata": {"name": "x"},
            "spec": {
                "containers": [{
                    "name": "main",
                    "livenessProbe": {
                        "grpc": { "port": 9090 }
                    }
                }]
            }
        });
        let ops = build_patch(&pod, &InjectorConfig::default());
        assert!(
            !ops.iter().any(|op| op
                .get("path")
                .and_then(|v| v.as_str())
                .map_or(false, |p| p.contains("livenessProbe"))),
            "grpc probes must not be rewritten — got ops {:#?}",
            ops
        );
    }

    #[test]
    fn probe_rewrite_handles_multi_container_pods() {
        let pod = json!({
            "metadata": {"name": "x"},
            "spec": {
                "containers": [
                    {
                        "name": "first",
                        "livenessProbe": { "httpGet": { "path": "/h", "port": 8001 } }
                    },
                    {
                        "name": "second",
                        "readinessProbe": { "httpGet": { "path": "/r", "port": 8002 } }
                    }
                ]
            }
        });
        let ops = build_patch(&pod, &InjectorConfig::default());
        assert!(
            ops.iter().any(|op| op.get("path").unwrap()
                == "/spec/containers/0/livenessProbe/httpGet/port")
        );
        assert!(
            ops.iter().any(|op| op.get("path").unwrap()
                == "/spec/containers/1/readinessProbe/httpGet/port")
        );
    }

    #[test]
    fn aresta_sidecar_self_probes_mesh_probe_port() {
        let cfg = InjectorConfig::default();
        let sidecar = aresta_sidecar(&cfg);
        // mesh-probe port present.
        let ports = sidecar.pointer("/ports").unwrap().as_array().unwrap();
        assert!(
            ports.iter().any(|p| p.get("name").and_then(|v| v.as_str()) == Some("mesh-probe")
                && p.get("containerPort").and_then(|v| v.as_u64()) == Some(4191))
        );
        // Sidecar's own probes point at mesh-probe.
        let liv = sidecar.pointer("/livenessProbe/httpGet/port").unwrap();
        assert_eq!(liv, "mesh-probe");
        let liv_path = sidecar.pointer("/livenessProbe/httpGet/path").unwrap();
        assert_eq!(liv_path, "/live");
        let ready = sidecar.pointer("/readinessProbe/httpGet/port").unwrap();
        assert_eq!(ready, "mesh-probe");
        let ready_path = sidecar.pointer("/readinessProbe/httpGet/path").unwrap();
        assert_eq!(ready_path, "/ready");
    }

    #[test]
    fn iptables_rules_skip_probe_port() {
        let cfg = InjectorConfig::default();
        let init = iptables_init_container(&cfg, None);
        let args = init.pointer("/args/0").unwrap().as_str().unwrap();
        // Probe port 4191 RETURNs (not REDIRECTed to mTLS).
        assert!(
            args.contains("ARESTA_INBOUND -p tcp --dport 4191 -j RETURN"),
            "probe port 4191 must be excused from PREROUTING REDIRECT; got args:\n{args}"
        );
    }

    #[test]
    fn mesh_cidrs_emit_per_cidr_redirect_only() {
        let mut cfg = InjectorConfig::default();
        cfg.mesh_outbound_cidrs = vec!["10.42.0.0/16".into(), "10.43.0.0/16".into()];
        let init = iptables_init_container(&cfg, None);
        let args = init.pointer("/args/0").unwrap().as_str().unwrap();
        // Per-CIDR REDIRECT for both ranges.
        assert!(
            args.contains("ARESTA_OUTBOUND -p tcp -d 10.42.0.0/16 -j REDIRECT --to-port 15006"),
            "must emit per-CIDR REDIRECT for 10.42.0.0/16. got args:\n{args}"
        );
        assert!(
            args.contains("ARESTA_OUTBOUND -p tcp -d 10.43.0.0/16 -j REDIRECT --to-port 15006"),
            "must emit per-CIDR REDIRECT for 10.43.0.0/16. got args:\n{args}"
        );
        // The catch-all `-p tcp -j REDIRECT` (no -d) must NOT appear,
        // otherwise non-mesh egress (cloudflared → CF edge) loops.
        assert!(
            !args.contains("ARESTA_OUTBOUND -p tcp -j REDIRECT --to-port 15006"),
            "must NOT emit catch-all REDIRECT when mesh_outbound_cidrs set. got args:\n{args}"
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
