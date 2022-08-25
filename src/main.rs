/*
demo

token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1cmwxIjoiaHR0cDovL2h0dHBiaW4ub3JnL2dldD9hPTEiLCJ1cmwyIjoiaHR0cDovL2h0dHBiaW4ub3JnL2dldD9hPTIiLCJuYW1lIjoiY3NoIiwiaWF0IjoxOTE2MjM5MDIyfQ.Et2CO5FtuZNHmFo7d-Gc_b3LQWACvqhVFpj_liEIyig

header:
{
  "alg": "HS256",
  "typ": "JWT"
}

payload:
{
  "url1":"http://httpbin.org/get?a=1",
  "url2":"http://httpbin.org/get?a=2",
  "name": "csh",
  "iat": 1916239022
}

secret:
b"secret"

*/

use hmac::{Hmac, Mac};
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::Client;
use hyper::{Body, Method, Request, Response, StatusCode};
use jwt::{Header, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::net::TcpListener;

async fn fetch_url(url: hyper::Uri) -> hyper::Result<Response<Body>> {
    let client = Client::new();
    client.get(url).await
}

#[derive(Default, Deserialize, Serialize)]
struct Custom {
    url1: String,
    url2: String,
}

async fn handler_jwt(body: Body) -> Result<Response<Body>, hyper::Error> {
    let body_bytes = hyper::body::to_bytes(body).await?;
    let token_str = String::from_utf8(body_bytes.to_vec());
    if let Err(e) = token_str {
        let r = Response::builder()
            .status(400)
            .body(Body::from(e.to_string()))
            .unwrap();
        return Ok(r);
    }
    let token_str = token_str.unwrap();
    let key: Hmac<Sha256> = Hmac::new_from_slice(b"secret").unwrap();
    let token = VerifyWithKey::verify_with_key(token_str.as_str(), &key);

    if let Err(e) = token {
        let r = Response::builder()
            .status(400)
            .body(Body::from(e.to_string()))
            .unwrap();
        return Ok(r);
    }

    let token: Token<Header, Custom, _> = token.unwrap();
    let url1: Result<hyper::Uri, _> = token.claims().url1.clone().try_into();
    if let Err(e) = url1 {
        let r = Response::builder()
            .status(400)
            .body(Body::from(e.to_string()))
            .unwrap();
        return Ok(r);
    }
    let url1 = url1.unwrap();
    let resp = fetch_url(url1).await;
    println!("fetch url1 -> {}", resp.is_ok());

    let url2: Result<hyper::Uri, _> = token.claims().url2.clone().try_into();
    if let Err(e) = url2 {
        let r = Response::builder()
            .status(400)
            .body(Body::from(e.to_string()))
            .unwrap();
        return Ok(r);
    }
    let url2 = url2.unwrap();
    let resp = tokio::time::timeout(tokio::time::Duration::from_secs(10), fetch_url(url2)).await;
    match resp {
        Err(_) => Ok(Response::new(Body::from("timeout"))),
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Ok(Response::builder()
            .status(500)
            .body(Body::from(e.to_string()))
            .unwrap()),
    }
}

async fn router(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Simply echo the body back to the client.
        (&Method::POST, "/jwt") => handler_jwt(req.into_body()).await,

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("LISTEN").unwrap_or("0.0.0.0:3000".into());

    let listener = TcpListener::bind(&addr).await?;
    println!("Listening on http://{}", addr);
    loop {
        let (stream, _) = listener.accept().await?;

        tokio::task::spawn(async move {
            if let Err(err) = Http::new()
                .serve_connection(stream, service_fn(router))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
