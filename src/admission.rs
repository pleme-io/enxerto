//! Webhook decision layer — given an `AdmissionReview` + namespace
//! labels, decides whether to inject.

use serde::{Deserialize, Serialize};

/// Label that opts a pod (or namespace) into mesh injection.
pub const INJECT_LABEL: &str = "mesh.pleme.io/inject";

/// Annotation set on injected pods so re-admission is a no-op.
pub const INJECTED_ANNOTATION: &str = "mesh.pleme.io/injected";

/// Operator-tunable knobs (hard-coded to defaults for M2.2; M4
/// renderer makes these per-mesh).
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
    /// Where the proxy forwards plaintext to (matches the workload's
    /// listening port; today hardcoded — M4 makes it per-Servico).
    #[serde(default = "default_upstream_port")]
    pub upstream_port: u16,

    /// Name of the ConfigMap with the aresta proxy's `config.yaml`.
    /// Emitted by tatara-mesh-render as `<mesh-name>-aresta-config`;
    /// today hardcoded to the openclaw demo's name. M4-renderer-side
    /// can pass this in via a per-pod annotation in a follow-up.
    #[serde(default = "default_aresta_config_cm")]
    pub aresta_config_cm: String,
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
        }
    }
}

fn default_aresta_image() -> String {
    "ghcr.io/pleme-io/aresta:amd64-latest".into()
}
fn default_iptables_image() -> String {
    // Small busybox-based init image; iptables-restore lives at
    // /sbin/iptables-restore in BusyBox.
    "alpine/socat:1.7.4.4".into()
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
