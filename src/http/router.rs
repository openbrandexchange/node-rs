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

const UI_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'; sandbox";

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
    let h = r.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    if app.cfg.secure() {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    if ui {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(UI_CSP),
        );
        h.insert(
            "cross-origin-opener-policy",
            HeaderValue::from_static("same-origin"),
        );
    } else {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(API_CSP),
        );
    }
    if protocol {
        h.insert("obx-version", HeaderValue::from_static("0.3"));
    }
    if p == "/.well-known/obx" {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    r
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
    let ni = || any(protocol::not_implemented);
    let r = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
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
        .route("/obx/v1/exports", ni())
        .route("/obx/v1/exports/{*rest}", ni())
        .route("/obx/v1/usage", ni())
        .route("/obx/v1/webhooks", ni())
        .route("/obx/v1/webhooks/{*rest}", ni())
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
            get(admin::retailer_get).patch(admin::retailer_patch),
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
        .route("/admin/api/stats", get(admin::stats))
        .route("/obx/{*rest}", any(api_fallback))
        .route("/admin/api/{*rest}", any(api_fallback))
        .fallback(ui::serve)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::extract::DefaultBodyLimit::max(
            crate::app::MAX_IMPORT_BYTES as usize,
        ))
        .layer(middleware::from_fn_with_state(app.clone(), headers_mw))
        .with_state(app);
    r
}
