//! Webhook decision layer — given an `AdmissionReview` + namespace
//! labels, decides whether to inject.

use serde::{Deserialize, Serialize};

/// Label that opts a pod (or namespace) into mesh injection.
pub const INJECT_LABEL: &str = "mesh.pleme.io/inject";

/// Annotation set on injected pods so re-admission is a no-op.
pub const INJECTED_ANNOTATION: &str = "mesh.pleme.io/injected";

/// Optional per-pod annotation: override the default aresta-config
/// ConfigMap name. When set, the injector mounts this CM at
/// `/etc/aresta` instead of the operator-configured default.
pub const ARESTA_CONFIG_CM_ANNOTATION: &str = "enxerto.mesh.pleme.io/aresta-config-cm";

/// Optional per-pod annotation: comma-separated TCP ports to skip in
/// iptables PREROUTING + OUTPUT. Used to keep kubelet's plaintext
/// probes (HTTP on the workload's own port) from being redirected to
/// aresta-in's mTLS-only listener. e.g. "8082,8083" for cartorio+lacre.
pub const SKIP_INBOUND_PORTS_ANNOTATION: &str = "enxerto.mesh.pleme.io/skip-inbound-ports";

/// Operator-tunable knobs. Values come from `InjectorConfig::default`
/// + env-var overrides on the enxerto Deployment (`ARESTA_IMAGE`,
/// `MESH_OUTBOUND_CIDRS`). Per-pod overrides for `aresta_config_cm`
/// + skip-inbound ports flow through annotations on the pod itself
/// (see `ARESTA_CONFIG_CM_ANNOTATION`, `SKIP_INBOUND_PORTS_ANNOTATION`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InjectorConfig {
    /// Container image for the aresta proxy.
    #[serde(default = "default_aresta_image")]
    pub aresta_image: String,
    /// Container image for the iptables-redirect init-container.
    #[serde(default = "default_iptables_image")]
    pub iptables_image: String,
    /// CSI driver name for the SPIFFE Workload API socket.
    #[serde(default = "default_csi_driver")]
    pub spiffe_csi_driver: String,
    /// Inbound port the proxy listens on.
    #[serde(default = "default_inbound_port")]
    pub inbound_port: u16,
    /// Fallback target for aresta-in's plaintext forward — only
    /// consulted when SO_ORIGINAL_DST recovery fails. Real workload
    /// port is recovered transparently from the accepted socket.
    #[serde(default = "default_upstream_port")]
    pub upstream_port: u16,

    /// Default ConfigMap name with the aresta proxy's `config.yaml`.
    /// Each pod can override via the `ARESTA_CONFIG_CM_ANNOTATION`
    /// annotation — required for cross-namespace participants
    /// (cloudflared) whose CM lives in their own ns rather than the
    /// home mesh ns.
    #[serde(default = "default_aresta_config_cm")]
    pub aresta_config_cm: String,

    /// Image pull secrets to ensure on the injected pod (so the
    /// aresta sidecar can pull from ghcr if the package is private).
    /// Empty = no injection (assumes the workload's ServiceAccount or
    /// pod-level config already covers it).
    #[serde(default = "default_image_pull_secrets")]
    pub image_pull_secrets: Vec<String>,

    /// CIDRs whose outbound traffic should be transparently mTLS'd
    /// via aresta. Empty (default, backwards-compat) → REDIRECT all
    /// outbound TCP. Non-empty → only those CIDRs get REDIRECTed;
    /// everything else passes through unchanged. Set to the pod +
    /// service CIDR of the cluster to restrict the mesh to in-cluster
    /// east-west traffic and let egress (cloudflared → CF edge,
    /// workloads → public APIs, etc.) bypass.
    #[serde(default)]
    pub mesh_outbound_cidrs: Vec<String>,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            aresta_image: default_aresta_image(),
            iptables_image: default_iptables_image(),
            spiffe_csi_driver: default_csi_driver(),
            inbound_port: default_inbound_port(),
            upstream_port: default_upstream_port(),
            aresta_config_cm: default_aresta_config_cm(),
            image_pull_secrets: default_image_pull_secrets(),
            mesh_outbound_cidrs: Vec::new(),
        }
    }
}

fn default_aresta_image() -> String {
    // Compile-time fallback. Operator overrides via the
    // `ARESTA_IMAGE` env var on the enxerto Deployment so we don't
    // have to rebuild enxerto every time aresta ships. Pinned SHA
    // here so unmodified tests + dev environments still work.
    "ghcr.io/pleme-io/aresta:amd64-6a8a463".into()
}
fn default_iptables_image() -> String {
    // nicolaka/netshoot ships iptables, iproute2, curl, etc. — public
    // image, widely vendored in service-mesh init containers.
    //
    // **Plan goal #6 — digest-pinned, no `:latest`.** Pinned by sha256
    // to nicolaka/netshoot:v0.13 (released 2024-05-15) so every cluster
    // gets the exact same bytes the upstream maintainer cut a release
    // for. Operator overrides via `IPTABLES_IMAGE` env var on the
    // enxerto Deployment.
    //
    // Future cleanup: build a minimal pleme-io-attested iptables-only
    // image so the iptables init bears a cartorio admission record
    // like every other workload.
    "nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b".into()
}
fn default_csi_driver() -> String {
    "csi.spiffe.io".into()
}
fn default_inbound_port() -> u16 {
    15001
}
fn default_upstream_port() -> u16 {
    8080
}
fn default_aresta_config_cm() -> String {
    "openclaw-mesh-aresta-config".into()
}
fn default_image_pull_secrets() -> Vec<String> {
    vec!["ghcr-pull-secret".into()]
}

/// Decide whether to inject. Inputs:
///   - `pod_labels`     — labels on the pod being admitted.
///   - `pod_annotations` — annotations on the pod being admitted.
///   - `ns_labels`      — labels on the pod's namespace.
#[must_use]
pub fn decide(
    pod_labels: &serde_json::Map<String, serde_json::Value>,
    pod_annotations: &serde_json::Map<String, serde_json::Value>,
    ns_labels: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    if pod_annotations.get(INJECTED_ANNOTATION).and_then(|v| v.as_str()) == Some("true") {
        return false;
    }
    let pod_opted_in = pod_labels
        .get(INJECT_LABEL)
        .and_then(|v| v.as_str())
        .map_or(false, |v| v == "true");
    let ns_opted_in = ns_labels
        .get(INJECT_LABEL)
        .and_then(|v| v.as_str())
        .map_or(false, |v| v == "true");
    pod_opted_in || ns_opted_in
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(j: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        j.as_object().unwrap().clone()
    }

    #[test]
    fn pod_label_opts_in() {
        assert!(decide(
            &map(json!({"mesh.pleme.io/inject": "true"})),
            &map(json!({})),
            &map(json!({})),
        ));
    }

    #[test]
    fn ns_label_opts_in() {
        assert!(decide(
            &map(json!({})),
            &map(json!({})),
            &map(json!({"mesh.pleme.io/inject": "true"})),
        ));
    }

    #[test]
    fn already_injected_skips() {
        assert!(!decide(
            &map(json!({"mesh.pleme.io/inject": "true"})),
            &map(json!({"mesh.pleme.io/injected": "true"})),
            &map(json!({})),
        ));
    }

    #[test]
    fn no_opt_in_means_no_inject() {
        assert!(!decide(
            &map(json!({"app": "cartorio"})),
            &map(json!({})),
            &map(json!({"kubernetes.io/metadata.name": "openclaw"})),
        ));
    }
}
