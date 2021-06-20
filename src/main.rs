use std::sync::{Arc, RwLock};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use warp::{Filter, Rejection, Reply, reject};
use sha1::Sha1;
use hmac::{Hmac, Mac};

struct Job {
    app: String,
    result: RwLock<(String, Option<i32>)>,
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

fn verify_webhook_signature(webhook_secret: Vec<u8>) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::body::content_length_limit(1024 * 32)
        .and(warp::body::bytes())
        .and(warp::header::header("X-Hub-Signature"))
        .and_then(move |body: bytes::Bytes, signature: String| {
            let mut hmac = Hmac::<Sha1>::new_varkey(&webhook_secret).expect("failed to set up HMAC");
            hmac.input(body.as_ref());
            async move {
                hex::decode(&signature[5..])
                    .map_err(|err| reject::custom(InvalidSignature(format!("{}", err))))
                    .and_then(|sig| hmac.verify(&sig).map_err(|err| reject::custom(InvalidSignature(format!("{}", err)))))
            }
        })
        .untuple_one()
}

fn deploy_app(job: Arc<Job>, script: PathBuf) {
    let mut child = Command::new(&script)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut buf = String::new();
    while let Ok(n) = output.read_line(&mut buf) {
        if n == 0 { break; }
        job.result.write().unwrap().0 += buf.as_str();
        buf.clear();
    }

    match child.wait() {
        Ok(status) => {
            job.result.write().unwrap().1 = Some(status.code().unwrap_or(255));
        }
        Err(error) => {
            *job.result.write().unwrap() = (format!("Error: {}", error), Some(255));
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().unwrap();

    let jobs: Arc<RwLock<Vec<Arc<Job>>>> = Arc::default();
    
    let webhook_secret: String = std::env::var("github_webhook_secret").expect("`github_webhook_secret` environment variable must be set");
    let port: u16 = std::env::var("console_port")
        .expect("`console_port` environment variable must be set")
        .parse()
        .expect("`console_port` environment variable must be a number");
    let deploy = warp::path!("deploy" / String)
        .and(verify_webhook_signature(webhook_secret.into_bytes()))
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
                            deploy_app(job, script);
                        }
                    });

                    Ok(warp::reply::reply().into_response())
                }
            }
        });

    let console = warp::get()
        .and(warp::filters::path::end())
        .map(move || {
            let jobs = jobs.read().unwrap();
            let jobs_text = jobs.iter()
                .map(|job| {
                    let summary;
                    let details;
                    match &*job.result.read().unwrap() {
                        (output, Some(status)) => {
                            summary = format!("Exit code: {}", status);
                            details = output.clone();
                        }
                        (output, None) => {
                            summary = "Running...".into();
                            details = output.clone();
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
            warp::reply::html(format!(r#"
                <!DOCTYPE HTML>
                <html lang="en">
                    <head>
                        <title>Jobs</title>
                        <meta charset="utf-8" />
                    <body>{}</body>
                </html>
            "#, jobs_text).trim().to_owned())
        });

    warp::serve(deploy.or(console)).run(([127, 0, 0, 1], port)).await;
}
