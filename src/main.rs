use warp::{Filter, Rejection, reject};
use sha1::Sha1;
use hmac::{Hmac, Mac};

#[derive(Debug)]
struct InvalidSignature;
impl reject::Reject for InvalidSignature {}

fn verify_signature(secret: Vec<u8>) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::body::content_length_limit(1024 * 32)
        .and(warp::body::bytes())
        .and(warp::header::header("X-Hub-Signature"))
        .and_then(move |body: bytes::Bytes, signature: String| {
            let mut hmac = Hmac::<Sha1>::new_varkey(&secret).expect("failed to set up HMAC");
            hmac.reset();
            hmac.input(body.as_ref());
            let result = hmac.verify(signature.as_bytes());
            async move {
                match result {
                    Ok(()) => Ok(()),
                    Err(..) => Err(reject::custom(InvalidSignature)),
                }
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
        .and(verify_signature(secret.as_bytes().to_owned()))
        .map(|app| {
            format!("Deploying {}", app)
        });
    warp::serve(deploy).run(([127, 0, 0, 1], port)).await;
}
