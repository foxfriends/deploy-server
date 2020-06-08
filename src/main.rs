use std::path::PathBuf;
use std::process::Command;
use warp::{Filter, Rejection, Reply, reject, http::StatusCode};
use sha1::Sha1;
use hmac::{Hmac, Mac};

#[derive(Debug)]
struct InvalidSignature(String);
impl reject::Reject for InvalidSignature {}

#[derive(Debug)]
struct InvalidApplication;
impl reject::Reject for InvalidApplication {}

#[derive(Debug)]
struct FailedDeploy;
impl reject::Reject for FailedDeploy {}

fn verify_signature(secret: Vec<u8>) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::body::content_length_limit(1024 * 32)
        .and(warp::body::bytes())
        .and(warp::header::header("X-Hub-Signature"))
        .and_then(move |body: bytes::Bytes, signature: String| {
            let mut hmac = Hmac::<Sha1>::new_varkey(&secret).expect("failed to set up HMAC");
            hmac.input(body.as_ref());
            async move {
                hex::decode(&signature[5..])
                    .map_err(|err| reject::custom(InvalidSignature(format!("{}", err))))
                    .and_then(|sig| hmac.verify(&sig).map_err(|err| reject::custom(InvalidSignature(format!("{}", err)))))
            }
        })
        .untuple_one()
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().unwrap();
    let secret: String = std::env::var("github_webhook_secret").expect("`github_webhook_secret` environment variable must be set");
    let port: u16 = std::env::var("console_port")
        .expect("`console_port` environment variable must be set")
        .parse()
        .expect("`console_port` environment variable must be a number");
    let deploy = warp::path!("deploy" / String)
        .and(verify_signature(secret.into_bytes()))
        .and_then(|app| async move {
            let script = PathBuf::from(format!("{}.deploy", app));
            if !script.is_file() {
                return Err(reject::custom(InvalidApplication));
            }
            match Command::new(&script).status() {
                Ok(status) if status.success() => Ok(warp::reply::reply().into_response()),
                Ok(status) => Ok(warp::reply::with_status(format!("{}: Deploy failed. Exit code: {}", script.display(), status.code().unwrap()), StatusCode::INTERNAL_SERVER_ERROR).into_response()),
                Err(error) => Ok(warp::reply::with_status(format!("{}: Deploy failed. Error: {}", script.display(), error), StatusCode::INTERNAL_SERVER_ERROR).into_response()),
            }
        });
    warp::serve(deploy).run(([127, 0, 0, 1], port)).await;
}
