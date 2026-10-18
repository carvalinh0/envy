//! Test harness: runs real CLI arguments through the real command handlers, with the
//! operating-system dependencies (keyring, terminal, child processes) replaced by fakes.
#![allow(dead_code)]

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    fs,
    path::PathBuf,
};

use anyhow::{Result, anyhow};
use clap::Parser;
use dot_envy::{
    app,
    bundle::AesGcmCodec,
    cli::Cli,
    config::Config,
    context::Context,
    envy::{Envy, GLOBAL_ENV, Schema, VarDetail},
    inference::HeuristicInferrer,
    prompt::Prompter,
    runner::ProcessRunner,
    schema::Secret,
    state::FileState,
    update::{ReleaseSource, SelfUpdater, UpdateMethod},
    vault::{MemoryVault, SecretVault},
};
use tempfile::TempDir;

pub const PROJECT_ID: &str = "proj-1";

#[derive(Default)]
pub struct FakePrompter {
    answers: RefCell<VecDeque<String>>,
    pub asked: RefCell<Vec<String>>,
}

impl FakePrompter {
    pub fn answers(&self, values: &[&str]) {
        self.answers
            .borrow_mut()
            .extend(values.iter().map(|v| v.to_string()));
    }
}

impl Prompter for FakePrompter {
    fn ask_secret(&self, label: &str) -> Result<Secret> {
        self.asked.borrow_mut().push(label.to_string());
        let answer = self
            .answers
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| anyhow!("the test did not provide an answer for '{label}'"))?;
        Ok(Secret::new(answer))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub program: String,
    pub args: Vec<String>,
    pub envs: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct FakeRunner {
    pub calls: RefCell<Vec<Call>>,
    pub exit_code: Cell<i32>,
}

impl ProcessRunner for FakeRunner {
    fn run(&self, program: &str, args: &[String], envs: &[(String, Secret)]) -> Result<i32> {
        self.calls.borrow_mut().push(Call {
            program: program.to_string(),
            args: args.to_vec(),
            envs: envs
                .iter()
                .map(|(k, v)| (k.clone(), v.expose_secret().to_string()))
                .collect(),
        });
        Ok(self.exit_code.get())
    }
}

/// Releases published on GitHub. `latest: None` simulates being offline.
#[derive(Default)]
pub struct FakeReleases {
    pub latest: RefCell<Option<String>>,
    pub queries: Cell<usize>,
}

impl FakeReleases {
    pub fn publish(&self, tag: &str) {
        *self.latest.borrow_mut() = Some(tag.to_string());
    }
}

impl ReleaseSource for FakeReleases {
    fn latest_tag(&self) -> Result<String> {
        self.queries.set(self.queries.get() + 1);
        self.latest
            .borrow()
            .clone()
            .ok_or_else(|| anyhow!("offline"))
    }

    fn download(&self, _tag: &str, _asset: &str) -> Result<Vec<u8>> {
        Err(anyhow!("the fake never serves files"))
    }
}

/// Records the updates it was asked to apply instead of touching the executable.
pub struct FakeUpdater {
    pub applied: RefCell<Vec<String>>,
    pub method: Cell<UpdateMethod>,
    pub fail: Cell<bool>,
}

impl Default for FakeUpdater {
    fn default() -> Self {
        Self {
            applied: RefCell::default(),
            method: Cell::new(UpdateMethod::Binary),
            fail: Cell::new(false),
        }
    }
}

impl SelfUpdater for FakeUpdater {
    fn apply(&self, tag: &str, _releases: &dyn ReleaseSource) -> Result<UpdateMethod> {
        self.applied.borrow_mut().push(tag.to_string());
        if self.fail.get() {
            return Err(anyhow!("could not replace the executable"));
        }
        Ok(self.method.get())
    }
}

pub struct Harness {
    pub dir: TempDir,
    pub config: Config,
    pub vault: MemoryVault,
    pub state: FileState,
    pub prompter: FakePrompter,
    pub runner: FakeRunner,
    pub releases: FakeReleases,
    pub updater: FakeUpdater,
}

impl Harness {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::new(dir.path(), "envy.json", "schemas/v1.json");
        let state = FileState::new(config.state_path());
        Self {
            dir,
            config,
            vault: MemoryVault::new(),
            state,
            prompter: FakePrompter::default(),
            runner: FakeRunner::default(),
            releases: FakeReleases::default(),
            updater: FakeUpdater::default(),
        }
    }

    /// Works as if Envy was started in `relative` (created if needed), like `cd` followed by
    /// the project discovery `main` does.
    pub fn cd(&mut self, relative: &str) {
        let dir = self.dir.path().join(relative);
        fs::create_dir_all(&dir).unwrap();
        self.config =
            Config::new(&dir, &self.config.file_name, &self.config.schema_path).discover();
        self.state = FileState::new(self.config.state_path());
    }

    /// Marks the temporary directory as a repository root, so the searches that walk up
    /// the tree stop there.
    pub fn git_init(&self) {
        fs::create_dir_all(self.path(".git")).unwrap();
    }

    /// Writes `envy` as `<relative>/envy.json`.
    pub fn save_manifest(&self, relative: &str, envy: &Envy) {
        let dir = self.path(relative);
        fs::create_dir_all(&dir).unwrap();
        envy.save(&dir.join("envy.json")).unwrap();
    }

    pub fn manifest_at(&self, relative: &str) -> Envy {
        Envy::load_from_file(&self.path(relative).join("envy.json")).unwrap()
    }

    /// A harness with the sample manifest already written.
    pub fn with_manifest() -> Self {
        let harness = Self::new();
        sample_envy().save(&harness.config.manifest_path()).unwrap();
        harness
    }

    /// Runs `envy <args>`; returns the exit code and everything written to stdout.
    pub fn run(&self, args: &[&str]) -> Result<(i32, String)> {
        let (result, out) = self.run_output(args);
        result.map(|code| (code, out))
    }

    /// Like [`Harness::run`], but keeps what was written to stdout when the command fails.
    pub fn run_output(&self, args: &[&str]) -> (Result<i32>, String) {
        let cli = match Cli::try_parse_from(std::iter::once("envy").chain(args.iter().copied())) {
            Ok(cli) => cli,
            Err(err) => return (Err(anyhow!("{err}")), String::new()),
        };

        let ctx = Context {
            config: &self.config,
            vault: &self.vault,
            state: &self.state,
            prompter: &self.prompter,
            runner: &self.runner,
            codec: &AesGcmCodec,
            inferrer: &HeuristicInferrer,
            releases: &self.releases,
            updater: &self.updater,
        };

        let mut out = Vec::new();
        let result = app::dispatch(cli.command, &ctx, &mut out);
        (result, String::from_utf8(out).unwrap())
    }

    pub fn ok(&self, args: &[&str]) -> String {
        match self.run(args) {
            Ok((_, out)) => out,
            Err(err) => panic!("`envy {}` failed: {err:#}", args.join(" ")),
        }
    }

    pub fn err(&self, args: &[&str]) -> String {
        match self.run(args) {
            Ok((_, out)) => panic!(
                "`envy {}` should have failed, it printed:\n{out}",
                args.join(" ")
            ),
            Err(err) => format!("{err:#}"),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn write(&self, name: &str, content: &str) {
        let path = self.path(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    pub fn manifest(&self) -> Envy {
        Envy::load_from_file(&self.config.manifest_path()).unwrap()
    }

    pub fn stored(&self, project: &str, env: &str, key: &str) -> Option<String> {
        self.vault
            .get(project, env, key)
            .unwrap()
            .map(|s| s.expose_secret().to_string())
    }
}

pub fn var(kind: &str, default: Option<&str>) -> VarDetail {
    VarDetail {
        kind: kind.to_string(),
        default: default.map(str::to_string),
    }
}

/// `dev` and `prod` environments plus a `global` one.
pub fn sample_envy() -> Envy {
    let mut envy = Envy::new("Sample".into(), Some("schemas/v1.json".into())).unwrap();
    envy.id = PROJECT_ID.into();
    envy.schemas.insert(
        "dev".into(),
        Schema::from([
            ("PORT".to_string(), var("port", Some("3000"))),
            ("DATABASE_URL".to_string(), var("url", None)),
            ("API_TOKEN".to_string(), var("secret", None)),
        ]),
    );
    envy.schemas.insert(
        "prod".into(),
        Schema::from([
            ("DATABASE_URL".to_string(), var("url", None)),
            ("API_TOKEN".to_string(), var("secret", None)),
        ]),
    );
    envy.schemas.insert(
        GLOBAL_ENV.into(),
        Schema::from([("APP_NAME".to_string(), var("string", Some("envy")))]),
    );
    envy.checksum = envy.compute_checksum().unwrap();
    envy
}
