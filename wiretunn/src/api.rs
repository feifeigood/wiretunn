use axum::{http::StatusCode, routing::get, Json, Router};
use serde_json::json;

pub fn router() -> Router {
    let mut r = Router::new();

    r = r.route(
        "/version",
        get(|| async {
            (
                StatusCode::OK,
                Json(json!({"version":env!("CARGO_PKG_VERSION")})),
            )
        }),
    );

    r
}
