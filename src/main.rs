use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::future::ready;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use warp::{reject, Filter, Rejection, Reply};

struct Job {
    app: String,
    result: RwLock<(String, Option<i32>)>,
}

impl Job {
    fn new(app: String) -> Self {
        Self {
            app,
            result: RwLock::default(),
        }
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

fn verify_webhook_signature(
    webhook_secret: Vec<u8>,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::body::content_length_limit(1024 * 32)
        .and(warp::body::bytes())
        .and(warp::header::header("X-Hub-Signature"))
        .and_then(move |body: bytes::Bytes, signature: String| {
            let mut hmac =
                Hmac::<Sha1>::new_from_slice(&webhook_secret).expect("failed to set up HMAC");
            hmac.update(body.as_ref());
            async move {
                hex::decode(&signature[5..])
                    .map_err(|err| reject::custom(InvalidSignature(format!("{}", err))))
                    .and_then(|sig| {
                        hmac.verify_slice(&sig)
                            .map_err(|err| reject::custom(InvalidSignature(format!("{}", err))))
                    })
            }
        })
        .untuple_one()
}

fn verify_actions_secret(
    actions_secret: String,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::header::header("X-Deploy-Secret")
        .and_then(move |secret: String| {
            if secret == actions_secret {
                ready(Ok(()))
            } else {
                ready(Err(reject::custom(InvalidSignature(String::from(
                    "Invalid secret",
                )))))
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
        if n == 0 {
            break;
        }
        job.result.write().unwrap().0 += buf.as_str();
        buf.clear();
    }

    match child.wait() {
        Ok(status) => {
            if !status.success() {
                let mut err = String::new();
                child.stderr.take().unwrap().read_to_string(&mut err).ok();
                let mut job = job.result.write().unwrap();
                job.0 += "\nSTDERR:\n";
                job.0 += err.as_str();
            }
            job.result.write().unwrap().1 = Some(status.code().unwrap_or(255));
        }
        Err(error) => {
            *job.result.write().unwrap() = (format!("Error: {}", error), Some(255));
        }
    }
}

async fn resolve_deploy_script(app: String) -> Result<(String, PathBuf), Rejection> {
    let script = std::env::current_dir()
        .unwrap()
        .join(format!("{}.deploy", app));
    if !script.is_file() {
        return Err(reject::custom(InvalidApplication));
    }
    Ok((app, script))
}

type Jobs = Arc<RwLock<Vec<Arc<Job>>>>;

fn with_jobs(
    jobs: Jobs,
) -> impl Filter<Extract = (Jobs,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || jobs.clone())
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().unwrap();

    let jobs: Arc<RwLock<Vec<Arc<Job>>>> = Arc::default();

    let webhook_secret: String = std::env::var("github_webhook_secret")
        .expect("`github_webhook_secret` environment variable must be set");
    let actions_secret: String = std::env::var("github_actions_secret")
        .expect("`github_actions_secret` environment variable must be set");
    let port: u16 = std::env::var("console_port")
        .expect("`console_port` environment variable must be set")
        .parse()
        .expect("`console_port` environment variable must be a number");
    let deploy = warp::path!("deploy" / String)
        .and(verify_webhook_signature(webhook_secret.into_bytes()))
        .and_then(resolve_deploy_script)
        .and(with_jobs(jobs.clone()))
        .and_then(|(app, script): (String, PathBuf), jobs: Jobs| {
            std::thread::spawn({
                let app = app.clone();
                move || {
                    let job = Arc::new(Job::new(app));
                    jobs.write().unwrap().push(job.clone());
                    deploy_app(job, script);
                }
            });

            ready(Ok::<_, Rejection>(warp::reply::reply().into_response()))
        });
    let deploy2 = warp::path!("deploy2" / String)
        .and(verify_actions_secret(actions_secret))
        .and_then(resolve_deploy_script)
        .and(with_jobs(jobs.clone()))
        .and_then(|(app, script): (String, PathBuf), jobs: Jobs| {
            std::thread::spawn({
                let app = app.clone();
                move || {
                    let job = Arc::new(Job::new(app));
                    jobs.write().unwrap().push(job.clone());
                    deploy_app(job, script);
                }
            });

            ready(Ok::<_, Rejection>(warp::reply::reply().into_response()))
        });

    let console = warp::get().and(warp::filters::path::end()).map(move || {
        let jobs = jobs.read().unwrap();
        let jobs_text = jobs
            .iter()
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
                format!(
                    r#"
                    <div>
                        <div>
                            <b>App:</b> {}
                        </div>
                        <details>
                            <summary>{}</summary>
                            <pre>{}</pre>
                        </details>
                    </div>
                    "#,
                    job.app, summary, details
                )
            })
            .collect::<String>();
        warp::reply::html(
            format!(
                r#"
                <!DOCTYPE HTML>
                <html lang="en">
                    <head>
                        <title>Jobs</title>
                        <meta charset="utf-8" />
                    <body>{}</body>
                </html>
            "#,
                jobs_text
            )
            .trim()
            .to_owned(),
        )
    });

    warp::serve(deploy.or(deploy2).or(console))
        .run(([127, 0, 0, 1], port))
        .await;
}
