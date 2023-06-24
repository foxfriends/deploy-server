use futures::stream::iter;
use futures::stream::select_all::select_all;
use futures::{join, FutureExt, StreamExt};
use std::future::ready;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio_stream::wrappers::LinesStream;
use uuid::Uuid;
use warp::{reject, Filter, Rejection, Reply};

#[derive(Clone)]
enum OutputLine {
    Stdout(String),
    Stderr(String),
}

#[derive(Default)]
struct JobResult {
    output: Vec<OutputLine>,
    status: Option<i32>,
}

struct Job {
    id: Uuid,
    app: String,
    result: RwLock<JobResult>,
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
struct InvalidSignature;
impl reject::Reject for InvalidSignature {}

#[derive(Debug)]
struct InvalidApplication;
impl reject::Reject for InvalidApplication {}

fn verify_actions_secret(
    actions_secret: String,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::header::header("X-Deploy-Secret")
        .and_then(move |secret: String| {
            let is_valid = secret == actions_secret;
            async move {
                if is_valid {
                    Ok(())
                } else {
                    Err(reject::custom(InvalidSignature))
                }
            }
        })
        .untuple_one()
}

async fn deploy_app(job: Arc<Job>, script: PathBuf) {
    let mut child = Command::new(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let stdout = LinesStream::new(BufReader::new(child.stdout.take().unwrap()).lines())
        .filter_map(|line| ready(line.ok()))
        .map(OutputLine::Stdout)
        .boxed();
    let stderr = LinesStream::new(BufReader::new(child.stderr.take().unwrap()).lines())
        .filter_map(|line| ready(line.ok()))
        .map(OutputLine::Stderr)
        .boxed();

    let consume = select_all(vec![stdout, stderr]).for_each({
        let job = job.clone();
        move |line| {
            let job = job.clone();
            async move { job.result.write().await.output.push(line) }
        }
    });
    let complete = child.wait().then(move |result| async move {
        let status = result
            .map(|status| status.code())
            .ok()
            .flatten()
            .unwrap_or(255);
        job.result.write().await.status = Some(status);
    });

    join!(consume, complete);
}

async fn resolve_deploy_script(app: String) -> Result<(String, PathBuf), Rejection> {
    let script = std::env::current_dir()
        .unwrap()
        .join(format!("{app}.deploy"));
    if script.is_file() {
        Ok((app, script))
    } else {
        Err(reject::custom(InvalidApplication))
    }
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
    output: Vec<OutputLine>,
}

impl TemplateJob {
    async fn from(job: &Job) -> Self {
        let result = job.result.read().await;
        TemplateJob {
            id: job.id,
            app: job.app.clone(),
            summary: match result.status {
                Some(status) => format!("Exit code: {status}"),
                None => "Running...".to_owned(),
            },
            output: result.output.clone(),
        }
    }
}

#[derive(askama::Template)]
#[template(path = "index.html")]
struct Index {
    jobs: Vec<TemplateJob>,
}

#[tokio::main(flavor = "current_thread")]
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
        .and_then(|(app, script): (String, PathBuf), jobs: Jobs| async move {
            let job = Arc::new(Job::new(app.to_owned()));
            jobs.write().await.push(job.clone());
            tokio::spawn(deploy_app(job, script));

            Ok::<_, Rejection>(warp::reply::reply().into_response())
        });

    let console = warp::get()
        .and(warp::filters::path::end())
        .and(with_jobs(jobs))
        .then(|jobs: Jobs| async move {
            let jobs: Vec<_> = iter(jobs.read().await.iter())
                .then(|job| TemplateJob::from(job.as_ref()))
                .collect()
                .await;
            Index { jobs }
        });

    warp::serve(deploy2.or(console))
        .run(([127, 0, 0, 1], port))
        .await;
}
