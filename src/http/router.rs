//! Routes and the middleware every response passes (security headers,
//! OBX-Version, setup gate for the protocol).

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, head, post, put};

use super::{access, admin, feed, ingest, protocol, ui};
use crate::app::App;
use crate::problem::Problem;

async fn headers_mw(State(app): State<App>, req: Request, next: Next) -> Response {
    let p = req.uri().path().to_string();
    let protocol = p.starts_with("/obx/") || p == "/.well-known/obx";
    let ui = !protocol && !p.starts_with("/admin/api/") && p != "/healthz" && p != "/readyz";
    let setup_block = protocol && p != "/.well-known/obx" && !app.setup_done().await;
    let mut r = if setup_block {
        Problem::new("setup_required", "This node has not been set up yet.")
            .with_status(503)
            .into_response()
    } else {
        next.run(req).await
    };
    let surface = if protocol {
        obx_axum::Surface::Protocol
    } else if ui {
        obx_axum::Surface::Ui
    } else {
        obx_axum::Surface::Api
    };
    obx_axum::security_headers(r.headers_mut(), surface, app.cfg.secure());
    let h = r.headers_mut();
    if p == "/.well-known/obx" {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    r
}

/// Request id, access log and request metrics for every request.
async fn observe_mw(State(app): State<App>, mut req: Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            (8..=128).contains(&v.len())
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:/=+-".contains(&b))
        })
        .map(String::from)
        .unwrap_or_else(|| hex::encode(rand::random::<[u8; 12]>()));
    req.extensions_mut()
        .insert(crate::audit::RequestId(id.clone()));
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let mut r = next.run(req).await;
    let route = crate::metrics::route_label(
        r.extensions()
            .get::<crate::metrics::RouteLabel>()
            .map(|l| l.0.as_str()),
    );
    let status = r.status().as_u16();
    let d = start.elapsed();
    app.metrics.observe(&method, &route, status, d);
    let quiet = matches!(path.as_str(), "/healthz" | "/readyz" | "/metrics");
    let ms = d.as_secs_f64() * 1000.0;
    if status >= 500 {
        tracing::error!(request_id = %id, method, route, path, status, duration_ms = ms, "http");
    } else if app.cfg.access_log && !quiet {
        tracing::info!(request_id = %id, method, route, path, status, duration_ms = ms, "http");
    } else {
        tracing::debug!(request_id = %id, method, route, path, status, duration_ms = ms, "http");
    }
    if let Ok(v) = HeaderValue::from_str(&id) {
        r.headers_mut().insert("x-request-id", v);
    }
    r
}

/// Route layer: the matched pattern travels to the outer layer.
async fn route_label_mw(
    matched: Option<axum::extract::MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let label = matched.map(|m| m.as_str().to_string());
    let mut r = next.run(req).await;
    if let Some(l) = label {
        r.extensions_mut().insert(crate::metrics::RouteLabel(l));
    }
    r
}

/// The readiness probe: not shutting down, the database answers on the
/// current schema and the file store is reachable.
async fn readyz(State(app): State<App>) -> Response {
    let mut ready = true;
    let mut checks = serde_json::json!({"database": "ok", "files": "ok", "shutdown": "ok"});
    if app.draining.load(std::sync::atomic::Ordering::SeqCst) {
        checks["shutdown"] = "shutting down".into();
        ready = false;
    }
    let v = app
        .db
        .read(|c| {
            Ok(c.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await;
    if v.is_err() {
        checks["database"] = "unavailable".into();
        ready = false;
    }
    if app.store.check().await.is_err() {
        checks["files"] = "unavailable".into();
        ready = false;
    }
    super::json(
        if ready { 200 } else { 503 },
        &serde_json::json!({"status": if ready { "ready" } else { "not_ready" }, "version": crate::app::VERSION,
            "schema_version": v.unwrap_or(0), "checks": checks}),
    )
}

async fn healthz(State(app): State<App>) -> Response {
    match app
        .db
        .read(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
        .await
    {
        Ok(_) => (StatusCode::OK, "ok\n").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable\n").into_response(),
    }
}

async fn discovery_options() -> Response {
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET"),
    );
    r
}

async fn api_fallback(method: Method) -> Problem {
    let _ = method;
    Problem::new("not_found", "There is nothing here.")
}

async fn method_not_allowed() -> Problem {
    Problem::new("method_not_allowed", "This method is not supported here.")
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/.well-known/obx",
            get(protocol::discovery).options(discovery_options),
        )
        .route("/obx/v1/access-requests", post(access::create))
        .route("/obx/v1/access-requests/{id}", get(access::status))
        .route("/obx/v1/oauth/token", post(protocol::token))
        .route("/obx/v1/grant", get(protocol::grant))
        .route("/obx/v1/changes", get(feed::changes))
        .route("/obx/v1/brands", get(protocol::brands))
        .route("/obx/v1/brands/{id}", get(protocol::brand))
        .route("/obx/v1/products", get(protocol::products))
        .route("/obx/v1/products/{id}", get(protocol::product))
        .route(
            "/obx/v1/products:by-gtin",
            get(protocol::by_gtin).post(protocol::by_gtin),
        )
        .route("/obx/v1/assets/{id}", get(protocol::asset))
        .route(
            "/obx/v1/assets/{id}/renditions/{name}",
            get(protocol::rendition),
        )
        // lane B: exports, usage, webhooks (protocol and brand)
        .route("/obx/v1/exports", post(crate::exports::h_create))
        .route("/obx/v1/exports/{id}", get(crate::exports::h_get))
        .route(
            "/obx/v1/exports/{id}/manifest",
            get(crate::exports::h_manifest),
        )
        .route(
            "/obx/v1/exports/{id}/parts/{n}",
            get(crate::exports::h_part),
        )
        .route("/obx/v1/usage", post(crate::usage::h_usage))
        .route(
            "/obx/v1/webhooks",
            get(crate::webhooks::h_list).post(crate::webhooks::h_create),
        )
        .route(
            "/obx/v1/webhooks/{id}",
            axum::routing::delete(crate::webhooks::h_delete),
        )
        .route("/obx/v1/webhooks/{id}/test", post(crate::webhooks::h_test))
        .route(
            "/admin/api/webhooks",
            get(crate::webhooks::admin_list).post(crate::webhooks::admin_create),
        )
        .route(
            "/admin/api/webhooks/{id}",
            axum::routing::patch(crate::webhooks::admin_patch)
                .delete(crate::webhooks::admin_delete),
        )
        .route(
            "/admin/api/webhooks/{id}/test",
            post(crate::webhooks::admin_test),
        )
        .route(
            "/admin/api/webhooks/{id}/deliveries",
            get(crate::webhooks::admin_deliveries),
        )
        // end lane B
        // Ingest API
        .route("/obx/v1/ingest", get(ingest::info))
        .route("/obx/v1/ingest/", get(ingest::info))
        .route("/obx/v1/ingest/batch", post(ingest::h_batch))
        .route(
            "/obx/v1/ingest/imports",
            post(crate::imports::h_ingest_import),
        )
        .route("/obx/v1/ingest/jobs", get(crate::jobs::h_jobs))
        .route("/obx/v1/ingest/jobs/{id}", get(crate::jobs::h_job))
        .route(
            "/obx/v1/ingest/jobs/{id}/results",
            get(crate::jobs::h_job_results),
        )
        .route("/obx/v1/ingest/uploads", post(crate::uploads::h_create))
        .route(
            "/obx/v1/ingest/uploads/{id}",
            get(crate::uploads::h_get).delete(crate::uploads::h_delete),
        )
        .route(
            "/obx/v1/ingest/uploads/{id}/parts/{n}",
            put(crate::uploads::h_part),
        )
        .route(
            "/obx/v1/ingest/uploads/{id}/complete",
            post(crate::uploads::h_complete),
        )
        .route(
            "/obx/v1/ingest/blobs/{sha}",
            head(ingest::h_head_blob).put(ingest::h_put_blob),
        )
        .route(
            "/obx/v1/ingest/products/{ext}/asset-order",
            put(ingest::h_asset_order),
        )
        .route(
            "/obx/v1/ingest/assets/{ext}/files/{name}",
            put(ingest::h_put_file),
        )
        .route(
            "/obx/v1/ingest/{seg}/{ext}",
            get(ingest::h_get)
                .put(ingest::h_put)
                .patch(ingest::h_patch)
                .delete(ingest::h_delete),
        )
        // Node Admin API
        .route("/admin/api/public/branding", get(admin::public_branding))
        .route("/admin/api/public/logo", get(admin::public_logo))
        .route(
            "/admin/api/setup",
            get(admin::setup_get).post(admin::setup_post),
        )
        .route("/admin/api/session", get(admin::session_get))
        .route("/admin/api/session/login", post(admin::login))
        .route("/admin/api/session/logout", post(admin::logout))
        .route("/admin/api/invites/{token}", get(admin::invite_get))
        .route(
            "/admin/api/invites/{token}/accept",
            post(admin::invite_accept),
        )
        .route("/admin/api/files/{sha}", get(admin::admin_file))
        .route(
            "/admin/api/settings",
            get(admin::settings_get).patch(admin::settings_patch),
        )
        .route(
            "/admin/api/settings/logo",
            put(admin::logo_put).delete(admin::logo_delete),
        )
        .route("/admin/api/catalog/brands", get(admin::catalog_brands))
        .route("/admin/api/catalog/products", get(admin::catalog_products))
        .route(
            "/admin/api/catalog/products/{ext}/asset-order",
            put(admin::catalog_asset_order),
        )
        .route(
            "/admin/api/catalog/assets/{ext}/files/{name}",
            put(admin::catalog_put_file),
        )
        .route(
            "/admin/api/catalog/blobs/{sha}",
            head(admin::catalog_head_blob).put(admin::catalog_put_blob),
        )
        .route(
            "/admin/api/catalog/{seg}/{ext}",
            get(admin::catalog_product)
                .put(admin::catalog_put)
                .patch(admin::catalog_patch)
                .delete(admin::catalog_delete),
        )
        .route(
            "/admin/api/imports",
            get(crate::imports::h_admin_imports).post(crate::imports::h_admin_import_create),
        )
        .route(
            "/admin/api/imports/{id}",
            get(crate::imports::h_admin_import),
        )
        .route(
            "/admin/api/imports/{id}/errors",
            get(crate::imports::h_admin_import_errors),
        )
        .route(
            "/admin/api/retailers",
            get(admin::retailers).post(admin::retailer_create),
        )
        .route(
            "/admin/api/retailers/{id}",
            get(admin::retailer_get)
                .patch(admin::retailer_patch)
                .delete(super::people::retailer_delete),
        )
        .route("/admin/api/access-requests", get(admin::access_requests))
        .route(
            "/admin/api/access-requests/{id}",
            get(admin::access_request),
        )
        .route(
            "/admin/api/access-requests/{id}/approve",
            post(admin::access_approve),
        )
        .route(
            "/admin/api/access-requests/{id}/reject",
            post(admin::access_reject),
        )
        .route("/admin/api/users", get(admin::users))
        .route("/admin/api/users/invites", post(admin::user_invite))
        .route(
            "/admin/api/api-clients",
            get(admin::api_clients).post(admin::api_client_create),
        )
        .route(
            "/admin/api/api-clients/{id}",
            axum::routing::delete(admin::api_client_revoke),
        )
        .route(
            "/admin/api/api-clients/{id}/rotate",
            post(admin::api_client_rotate),
        )
        .route(
            "/admin/api/ingest-tokens",
            get(admin::ingest_tokens).post(admin::ingest_token_create),
        )
        .route(
            "/admin/api/ingest-tokens/{id}",
            axum::routing::delete(admin::ingest_token_revoke),
        )
        .route(
            "/admin/api/ingest-tokens/{id}/rotate",
            post(admin::ingest_token_rotate),
        )
        .route("/admin/api/stats", get(crate::stats::h_stats))
        .route("/admin/api/stats/events", get(crate::stats::h_stats_events))
        .route(
            "/admin/api/me",
            axum::routing::patch(admin::me_patch).delete(super::people::me_delete),
        )
        // retailer portal
        .route("/admin/api/portal/viewer", get(super::portal::viewer))
        .route("/admin/api/portal/products", get(super::portal::products))
        .route("/admin/api/portal/facets", get(super::portal::facets))
        .route(
            "/admin/api/portal/products/data.csv",
            get(super::portal_downloads::products_csv),
        )
        .route(
            "/admin/api/portal/products/{id}",
            get(super::portal::product),
        )
        .route(
            "/admin/api/portal/products/{id}/download.zip",
            get(super::portal_downloads::product_zip),
        )
        .route(
            "/admin/api/portal/gtin-lookup",
            post(super::portal::gtin_lookup),
        )
        .route(
            "/admin/api/portal/selection",
            get(super::portal::selection_get)
                .put(super::portal::selection_put)
                .delete(super::portal::selection_delete),
        )
        .route(
            "/admin/api/portal/selection/download.zip",
            get(super::portal_downloads::selection_zip),
        )
        .route(
            "/admin/api/portal/selection/data.csv",
            get(super::portal_downloads::selection_csv),
        )
        .route(
            "/admin/api/portal/assets/{id}/download",
            get(super::portal_downloads::asset_download),
        )
        .route(
            "/admin/api/portal/download-jobs",
            get(super::portal_downloads::jobs).post(super::portal_downloads::job_create),
        )
        .route(
            "/admin/api/portal/download-jobs/{id}",
            get(super::portal_downloads::job_get),
        )
        .route(
            "/admin/api/portal/download-jobs/{id}/file",
            get(super::portal_downloads::job_file),
        )
        .route(
            "/admin/api/portal/api-clients",
            get(super::portal::clients).post(super::portal::client_create),
        )
        .route(
            "/admin/api/portal/api-clients/{id}",
            axum::routing::delete(super::portal::client_revoke),
        )
        .route(
            "/admin/api/portal/api-clients/{id}/rotate",
            post(super::portal::client_rotate),
        )
        // appearance
        .route(
            "/admin/api/public/favicon",
            get(crate::branding::public_favicon),
        )
        .route(
            "/admin/api/public/images/{id}",
            get(crate::branding::public_image),
        )
        .route(
            "/admin/api/settings/favicon",
            put(crate::branding::favicon_put).delete(crate::branding::favicon_delete),
        )
        .route(
            "/admin/api/settings/images",
            get(crate::branding::images).post(crate::branding::image_upload),
        )
        .route(
            "/admin/api/settings/images/{id}",
            axum::routing::delete(crate::branding::image_delete),
        )
        // lane C: scheduled imports
        .route(
            "/admin/api/import-sources",
            get(crate::sources::h_list).post(crate::sources::h_create),
        )
        .route(
            "/admin/api/import-sources/{id}",
            get(crate::sources::h_get)
                .patch(crate::sources::h_patch)
                .delete(crate::sources::h_delete),
        )
        .route(
            "/admin/api/import-sources/{id}/run",
            post(crate::sources::h_run),
        )
        .route(
            "/admin/api/import-sources/{id}/test",
            post(crate::sources::h_test),
        )
        // lane A: e-mail, people, personal data, audit log, metrics
        .route("/metrics", get(crate::metrics::handler))
        .route("/admin/api/password/forgot", post(super::people::forgot))
        .route("/admin/api/password/reset", post(super::people::reset))
        .route(
            "/admin/api/users/{id}",
            axum::routing::patch(super::people::user_patch).delete(super::people::user_delete),
        )
        .route(
            "/admin/api/users/{id}/resend-invite",
            post(super::people::user_resend_invite),
        )
        .route(
            "/admin/api/users/{id}/export",
            get(super::people::user_export),
        )
        .route(
            "/admin/api/retailers/{id}/export",
            get(super::people::retailer_export),
        )
        .route("/admin/api/me/export", get(super::people::me_export))
        .route(
            "/admin/api/import-template.csv",
            get(super::people::import_template),
        )
        .route("/admin/api/audit-log", get(crate::audit::h_list))
        // end lane A
        // demo mode (OBX_DEMO; answer 404 otherwise)
        .route("/admin/api/demo", get(crate::demo::h_info))
        .route("/admin/api/demo/login", post(crate::demo::h_login))
        .route("/admin/api/demo/reset", post(crate::demo::h_reset))
        // end demo mode
        .route("/obx/{*rest}", any(api_fallback))
        .route("/admin/api/{*rest}", any(api_fallback))
        .route_layer(middleware::from_fn_with_state(
            app.clone(),
            crate::audit::middleware,
        ))
        .route_layer(middleware::from_fn(route_label_mw))
        .fallback(ui::serve)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::extract::DefaultBodyLimit::max(
            crate::app::MAX_IMPORT_BYTES as usize,
        ))
        .layer(middleware::from_fn_with_state(
            app.clone(),
            crate::demo::guard,
        ))
        .layer(middleware::from_fn_with_state(app.clone(), headers_mw))
        .layer(middleware::from_fn_with_state(app.clone(), observe_mw))
        .with_state(app)
}
