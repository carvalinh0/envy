//! Reading `.env` files and discovering them in a directory.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::envy::GLOBAL_ENV;

/// Parses `KEY=VALUE` lines. Supports comments, blank lines, `export` and quoted values.
pub fn parse(content: &str) -> Result<Vec<(String, String)>> {
    let mut pairs: Vec<(String, String)> = Vec::new();

    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);

        let Some((key, value)) = line.split_once('=') else {
            bail!("Line {} is not a KEY=VALUE pair.", index + 1);
        };
        let key = key.trim();
        if key.is_empty() || key.contains(char::is_whitespace) {
            bail!("Line {} has an invalid variable name.", index + 1);
        }

        let value = unquote(value.trim());
        match pairs.iter_mut().find(|(k, _)| k == key) {
            Some(existing) => existing.1 = value,
            None => pairs.push((key.to_string(), value)),
        }
    }

    Ok(pairs)
}

fn unquote(value: &str) -> String {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return value[1..value.len() - 1].to_string();
        }
    }
    match value.find(" #") {
        Some(pos) => value[..pos].trim_end().to_string(),
        None => value.to_string(),
    }
}

/// A `.env.<name>` file found in the project directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvFile {
    /// Environment the file maps to (`.env.example` maps to [`GLOBAL_ENV`]).
    pub environment: String,
    pub path: PathBuf,
    /// `true` for `.env.example`: only the types are used, values are never stored or deleted.
    pub is_example: bool,
}

#[derive(Debug, Default)]
pub struct Discovery {
    pub files: Vec<DotenvFile>,
    /// Plain `.env` files: they carry no environment name, so they are reported and left alone.
    pub skipped: Vec<PathBuf>,
}

pub fn discover(dir: &Path) -> Result<Discovery> {
    let mut discovery = Discovery::default();

    let entries = fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().to_string();

        if file_name == ".env" {
            discovery.skipped.push(entry.path());
        } else if let Some(suffix) = file_name.strip_prefix(".env.")
            && !suffix.is_empty()
        {
            let is_example = suffix == "example";
            discovery.files.push(DotenvFile {
                environment: if is_example {
                    GLOBAL_ENV.to_string()
                } else {
                    suffix.to_string()
                },
                path: entry.path(),
                is_example,
            });
        }
    }

    discovery.files.sort_by(|a, b| a.path.cmp(&b.path));
    discovery.skipped.sort();
    Ok(discovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pairs_comments_and_blank_lines() {
        let pairs = parse("# comment\n\nA=1\nB = two\n").unwrap();
        assert_eq!(
            pairs,
            vec![("A".into(), "1".into()), ("B".into(), "two".into())]
        );
    }

    #[test]
    fn strips_quotes_export_and_inline_comments() {
        let pairs = parse("export A=\"x y\"\nB='z'\nC=value # trailing\nD=a#b\n").unwrap();
        assert_eq!(pairs[0].1, "x y");
        assert_eq!(pairs[1].1, "z");
        assert_eq!(pairs[2].1, "value");
        assert_eq!(pairs[3].1, "a#b");
    }

    #[test]
    fn keeps_equals_signs_inside_values() {
        let pairs = parse("URL=postgres://u:p@h/db?x=1\n").unwrap();
        assert_eq!(pairs[0].1, "postgres://u:p@h/db?x=1");
    }

    #[test]
    fn last_duplicate_wins() {
        let pairs = parse("A=1\nA=2\n").unwrap();
        assert_eq!(pairs, vec![("A".into(), "2".into())]);
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(parse("not a pair").is_err());
        assert!(parse("=value").is_err());
        assert!(parse("BAD KEY=1").is_err());
    }

    #[test]
    fn discovers_environment_files() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            ".env",
            ".env.development",
            ".env.production",
            ".env.example",
            "README.md",
        ] {
            fs::write(dir.path().join(name), "A=1").unwrap();
        }
        fs::create_dir(dir.path().join(".env.dir")).unwrap();

        let found = discover(dir.path()).unwrap();
        let mut envs: Vec<(&str, bool)> = found
            .files
            .iter()
            .map(|f| (f.environment.as_str(), f.is_example))
            .collect();
        envs.sort();
        assert_eq!(
            envs,
            vec![
                ("development", false),
                ("global", true),
                ("production", false)
            ]
        );
        assert_eq!(found.skipped.len(), 1);
    }
}
