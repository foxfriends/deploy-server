use std::sync::{Arc, RwLock};
use std::process::Command;
use warp::{Filter, Rejection, Reply, reject};
use sha1::Sha1;
use hmac::{Hmac, Mac};

struct Job {
    app: String,
    result: RwLock<Option<(String, u8)>>,
}

impl Job {
    fn new(app: String) -> Self {
        Self { app, result: RwLock::default() }
    }
}

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

    let jobs: Arc<RwLock<Vec<Arc<Job>>>> = Arc::default();
    
    let secret: String = std::env::var("github_webhook_secret").expect("`github_webhook_secret` environment variable must be set");
    let port: u16 = std::env::var("console_port")
        .expect("`console_port` environment variable must be set")
        .parse()
        .expect("`console_port` environment variable must be a number");
    let deploy = warp::path!("deploy" / String)
        .and(verify_signature(secret.into_bytes()))
        .and_then({
            let jobs = jobs.clone();
            move |app: String| {
                let jobs = jobs.clone();
                    async move {
                    let script = std::env::current_dir()
                        .unwrap()
                        .join(format!("{}.deploy", app));
                    if !script.is_file() {
                        return Err(reject::custom(InvalidApplication));
                    }

                    std::thread::spawn({
                        let app = app.clone();
                        move || {
                            let job = Arc::new(Job::new(app));
                            jobs.write().unwrap().push(job.clone());
                            match Command::new(&script).output() {
                                Ok(output) => {
                                    *job.result.write().unwrap() = Some((
                                        String::from_utf8(output.stdout).unwrap_or(String::from("Invalid Output")),
                                        output.status.code().unwrap_or(255) as u8
                                    ));
                                }
                                Err(error) => {
                                    *job.result.write().unwrap() = Some((format!("Error: {}", error), 255));
                                }
                            }
                        }
                    });

                    Ok(warp::reply::reply().into_response())
                }
            }
        });

    let console = warp::get()
        .and(warp::path("/"))
        .map(move || {
            let jobs = jobs.read().unwrap();
            let jobs_text = jobs.iter()
                .map(|job| {
                    let summary;
                    let details;
                    match &*job.result.read().unwrap() {
                        Some((output, status)) => {
                            summary = format!("Exit code: {}", status);
                            details = output.clone();
                        }
                        None => {
                            summary = "Running...".into();
                            details = "...".into();
                        }
                    };
                    format!(r#"
                    <div>
                        <div>
                            <b>App:</b> {}
                        </div>
                        <details>
                            <summary>{}</summary>
                            <pre>{}</pre>
                        </details>
                    </div>
                    "#, job.app, summary, details)
                })
                .collect::<String>();
            format!(r#"
                <!DOCTYPE HTML>
                <html lang="en">
                    <head>
                        <title>Jobs</title>
                        <meta charset="utf-8" />
                    <body>{}</body>
                </html>
            "#, jobs_text)
        });

    warp::serve(deploy.or(console)).run(([127, 0, 0, 1], port)).await;
}
