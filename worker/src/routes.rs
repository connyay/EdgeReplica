//! Non-RPC HTTP routes: `/healthz` and `/oauth/callback`.

use bytes::Bytes;
use connectrpc::ConnectRpcBody;
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use worker::HttpRequest;

/// Returns `Some(response)` if `req` matches a non-RPC route, else `None`
/// so the caller can dispatch into the ConnectRPC service.
pub fn try_handle(req: &HttpRequest) -> Option<Response<ConnectRpcBody>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => Some(text(StatusCode::OK, "ok")),
        // 503 on `/oauth/*` until OAuth is configured (rather than 404),
        // so clients distinguish "endpoint exists, deployment unconfigured"
        // from "wrong path".
        (_, p) if p.starts_with("/oauth/") => Some(text(
            StatusCode::SERVICE_UNAVAILABLE,
            "OAuth not configured on this deployment",
        )),
        _ => None,
    }
}

fn text(status: StatusCode, body: impl Into<Bytes>) -> Response<ConnectRpcBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ConnectRpcBody::Full(Full::new(body.into())))
        .expect("static response builder inputs are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use http_body_util::BodyExt;

    fn request(method: Method, uri: &str) -> HttpRequest {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(worker::Body::empty())
            .unwrap()
    }

    fn read_body(resp: Response<ConnectRpcBody>) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = block_on(resp.into_body().collect()).unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[test]
    fn healthz_ok() {
        let resp = try_handle(&request(Method::GET, "/healthz")).unwrap();
        let (status, body) = read_body(resp);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[test]
    fn rpc_paths_defer() {
        assert!(
            try_handle(&request(
                Method::POST,
                "/edgereplica.admin.v1.AdminService/Login",
            ))
            .is_none()
        );
    }

    #[test]
    fn oauth_path_returns_503_when_unconfigured() {
        let resp = try_handle(&request(Method::GET, "/oauth/github/callback")).unwrap();
        let (status, _body) = read_body(resp);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
