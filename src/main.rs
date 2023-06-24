use uuid::Uuid;
use std::future::ready;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use warp::{reject, Filter, Rejection, Reply};

struct Job {
    id: Uuid,
    app: String,
    result: RwLock<(String, Option<i32>)>,
}

impl Job {
    fn new(app: String) -> Self {
        Self {
            id: Uuid::new_v4(),
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
            *job.result.write().unwrap() = (format!("Error: {error}"), Some(255));
        }
    }
}

async fn resolve_deploy_script(app: String) -> Result<(String, PathBuf), Rejection> {
    let script = std::env::current_dir()
        .unwrap()
        .join(format!("{app}.deploy"));
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

struct TemplateJob {
    id: Uuid,
    app: String,
    summary: String,
    output: String,
}

impl From<&Job> for TemplateJob {
    fn from(job: &Job) -> Self {
        let (output, status) = &*job.result.read().unwrap();
        TemplateJob {
            id: job.id,
            app: job.app.clone(),
            summary: match status {
                Some(status) => format!("Exit code: {status}"),
                None => "Running...".to_owned(),
            },
            output: output.clone(),
        }
    }
}

#[derive(askama::Template)]
#[template(path = "index.html")]
struct Index {
    jobs: Vec<TemplateJob>,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().unwrap();

    let jobs: Arc<RwLock<Vec<Arc<Job>>>> = Arc::default();

    let actions_secret: String = std::env::var("github_actions_secret")
        .expect("`github_actions_secret` environment variable must be set");
    let port: u16 = std::env::var("console_port")
        .expect("`console_port` environment variable must be set")
        .parse()
        .expect("`console_port` environment variable must be a number");
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
        let jobs = jobs.read()
            .unwrap()
            .iter()
            .map(|job| job.as_ref().into())
            .collect::<Vec<_>>();
        Index { jobs }
    });

    warp::serve(deploy2.or(console))
        .run(([127, 0, 0, 1], port))
        .await;
}
