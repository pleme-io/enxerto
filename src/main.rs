//! enxerto — CLI entrypoint.
//!
//! Boots an axum TLS server that receives k8s `AdmissionReview`
//! requests and emits patched responses with mesh sidecars grafted
//! in.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Json, Router, extract::State, routing::post};
use base64::Engine;
use clap::Parser;
use enxerto::admission::{InjectorConfig, decide};
use enxerto::patch::build_patch;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(version, about = "enxerto — pleme-io mesh sidecar-injector")]
struct Args {
    /// Bind address for the webhook server (HTTPS).
    #[arg(long, env = "ENXERTO_LISTEN", default_value = "0.0.0.0:8443")]
    listen: String,

    /// PEM cert chain served to the K8s apiserver.
    #[arg(long, env = "ENXERTO_TLS_CERT", default_value = "/etc/enxerto/tls/tls.crt")]
    tls_cert: PathBuf,

    /// PEM private key.
    #[arg(long, env = "ENXERTO_TLS_KEY", default_value = "/etc/enxerto/tls/tls.key")]
    tls_key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 doesn't auto-pick a crypto provider; explicit install
    // before any TLS config is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install ring as the rustls default crypto provider");

    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,enxerto=debug")),
        )
        .json()
        .with_current_span(false)
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), listen = %args.listen, "enxerto starting");

    let mut injector_cfg = InjectorConfig::default();

    // Operator-provided aresta image override — avoids rebuilding
    // enxerto on every aresta version bump. The helm chart's
    // `arestaImage` value lands here; CI workflows set it from the
    // most-recently-published aresta tag.
    if let Ok(image) = std::env::var("ARESTA_IMAGE") {
        if !image.is_empty() {
            injector_cfg.aresta_image = image.clone();
            info!(image, "aresta image overridden from ARESTA_IMAGE env");
        }
    }

    // Comma-separated CIDRs to restrict the outbound REDIRECT to
    // (typically pod CIDR + service CIDR). When unset, the OUTPUT
    // chain redirects ALL outbound TCP — fine for pure east-west test
    // pods but breaks pods that egress to off-cluster destinations
    // (cloudflared → CF edge, workloads → public APIs). The helm
    // chart's `meshOutboundCidrs` value lands here.
    if let Ok(raw) = std::env::var("MESH_OUTBOUND_CIDRS") {
        injector_cfg.mesh_outbound_cidrs = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        info!(
            cidrs = ?injector_cfg.mesh_outbound_cidrs,
            "outbound mesh restricted to listed CIDRs (non-mesh egress passes through)"
        );
    }
    let cfg = Arc::new(injector_cfg);

    let app = Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route("/mutate", post(mutate))
        .with_state(cfg);

    let server_cfg = enxerto::tls::load_server_config(&args.tls_cert, &args.tls_key)
        .context("load TLS server config")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!(addr = %args.listen, "enxerto webhook listening");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(e) => {
                    warn!(peer = %peer, error = %e, "tls accept failed");
                    return;
                }
            };
            let svc = hyper::service::service_fn(move |req| {
                let app = app.clone();
                async move { app.oneshot(req).await }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
    }
}

use tower::ServiceExt;

async fn mutate(State(cfg): State<Arc<InjectorConfig>>, Json(body): Json<Value>) -> Json<Value> {
    let req_uid = body
        .pointer("/request/uid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let api_version = body
        .pointer("/apiVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("admission.k8s.io/v1")
        .to_string();

    let pod = match body.pointer("/request/object") {
        Some(p) => p,
        None => return reply_allow(&req_uid, &api_version, None),
    };
    let pod_labels = pod
        .pointer("/metadata/labels")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let pod_annotations = pod
        .pointer("/metadata/annotations")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    // The apiserver only passes the namespace *name* in
    // /request/namespace, not the full Namespace object. To be
    // ns-label-aware we'd need a kube-rs lookup at decision time;
    // for now the pod-level `mesh.pleme.io/inject` label is the
    // primary opt-in path, and the namespaceSelector on the MWC
    // (in lareira-enxerto's chart) excludes infra namespaces upfront.
    let ns_labels = serde_json::Map::new();

    if !decide(&pod_labels, &pod_annotations, &ns_labels) {
        debug!(uid = %req_uid, "skipping injection — no opt-in");
        return reply_allow(&req_uid, &api_version, None);
    }

    let ops = build_patch(pod, &cfg);
    let patch_json = serde_json::to_vec(&ops).expect("serialize patch");
    let patch_b64 = base64::engine::general_purpose::STANDARD.encode(&patch_json);
    info!(uid = %req_uid, ops = ops.len(), "injecting mesh sidecar");

    reply_allow(&req_uid, &api_version, Some(patch_b64))
}

fn reply_allow(uid: &str, api_version: &str, patch_b64: Option<String>) -> Json<Value> {
    let mut response = json!({
        "uid": uid,
        "allowed": true,
    });
    if let Some(p) = patch_b64 {
        response["patchType"] = json!("JSONPatch");
        response["patch"] = json!(p);
    }
    Json(json!({
        "apiVersion": api_version,
        "kind": "AdmissionReview",
        "response": response,
    }))
}
