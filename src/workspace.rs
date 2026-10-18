//! Finding manifests on disk: walking up to the project of the current directory, finding
//! the workspace root a project belongs to, and walking down a tree to list every project.
//!
//! The upward walks stop at the repository root (the first directory that contains `.git`),
//! so a manifest outside the repository is never picked up by accident.

use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};

use crate::envy::Envy;

/// Directories never searched when listing manifests: hidden ones (`.git`, `.venv`, ...) and
/// the usual dependency or build output folders.
const SKIPPED_DIRS: [&str; 5] = ["node_modules", "target", "vendor", "venv", "__pycache__"];

/// The directory itself, then its parents up to (and including) the repository root.
fn ancestors_within_repository(start: &Path) -> impl Iterator<Item = &Path> {
    let mut stop = false;
    start.ancestors().take_while(move |dir| {
        if stop {
            return false;
        }
        stop = is_repository_root(dir);
        true
    })
}

fn is_repository_root(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// Nearest directory, starting at `start` and going up, that contains `file_name`.
pub fn find_project_dir(start: &Path, file_name: &str) -> Option<PathBuf> {
    ancestors_within_repository(start)
        .find(|dir| dir.join(file_name).is_file())
        .map(Path::to_path_buf)
}

/// The repository that contains `start`, if any.
pub fn repository_root(start: &Path) -> Option<PathBuf> {
    ancestors_within_repository(start)
        .find(|dir| is_repository_root(dir))
        .map(Path::to_path_buf)
}

/// The nearest manifest above `project_dir` whose `workspace.members` include it.
pub fn find_root(project_dir: &Path, file_name: &str) -> Result<Option<(PathBuf, Envy)>> {
    for dir in ancestors_within_repository(project_dir).skip(1) {
        let path = dir.join(file_name);
        if !path.is_file() {
            continue;
        }
        let root = Envy::load_from_file(&path)?;
        let Some(workspace) = &root.workspace else {
            continue;
        };
        let Ok(relative) = project_dir.strip_prefix(dir) else {
            continue;
        };
        if workspace
            .members
            .iter()
            .any(|pattern| is_member(pattern, relative))
        {
            return Ok(Some((dir.to_path_buf(), root)));
        }
    }
    Ok(None)
}

/// Loads the manifest of `project_dir` and, when it is a workspace member, the root it
/// inherits from.
pub fn load_project(project_dir: &Path, file_name: &str) -> Result<Envy> {
    let mut envy = Envy::load_from_file(&project_dir.join(file_name))?;
    if let Some((_, root)) = find_root(project_dir, file_name)? {
        envy.parent = Some(Box::new(root));
    }
    Ok(envy)
}

/// Every manifest under `root` (including `root` itself), sorted by path.
pub fn find_manifests(root: &Path, file_name: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let manifest = dir.join(file_name);
        if manifest.is_file() {
            found.push(manifest);
        }
        let entries =
            fs::read_dir(&dir).with_context(|| format!("Could not read {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("Could not read {}", dir.display()))?;
            // `file_type` does not follow symbolic links, so links can never cause a loop.
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIPPED_DIRS.contains(&name.as_ref()) {
                continue;
            }
            pending.push(entry.path());
        }
    }

    found.sort();
    Ok(found)
}

/// Groups manifests by project id and keeps only the ids used by more than one manifest.
pub fn duplicated_ids(manifests: &[(PathBuf, String)]) -> BTreeMap<String, Vec<PathBuf>> {
    let mut by_id: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for (path, id) in manifests {
        by_id.entry(id.clone()).or_default().push(path.clone());
    }
    by_id.retain(|_, paths| paths.len() > 1);
    by_id
}

/// The other manifests of the repository (or workspace) that share the id of `project`.
pub fn manifests_sharing_id(
    project_dir: &Path,
    file_name: &str,
    envy: &Envy,
) -> Result<Vec<PathBuf>> {
    let scan_root = match repository_root(project_dir) {
        Some(root) => root,
        None => match find_root(project_dir, file_name)? {
            Some((root, _)) => root,
            None => return Ok(Vec::new()),
        },
    };

    let own = project_dir.join(file_name);
    let mut sharing = Vec::new();
    for path in find_manifests(&scan_root, file_name)? {
        if path == own {
            continue;
        }
        // Another project's broken manifest is reported by its own commands, not here.
        if Envy::load_from_file(&path).is_ok_and(|other| other.id == envy.id) {
            sharing.push(path);
        }
    }
    Ok(sharing)
}

/// Whether `relative` (a path relative to the workspace root) matches a `members` pattern.
///
/// Patterns are relative paths with `/` separators. In a segment `*` matches any run of
/// characters and `?` exactly one; a `**` segment matches any number of directories.
pub fn is_member(pattern: &str, relative: &Path) -> bool {
    let pattern: Vec<&str> = pattern
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let path: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    !path.is_empty() && match_segments(&pattern, &path)
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.split_first(), path.split_first()) {
        (None, None) => true,
        (Some((&"**", rest)), _) => {
            match_segments(rest, path) || (!path.is_empty() && match_segments(pattern, &path[1..]))
        }
        (Some((segment, rest)), Some((part, path_rest))) => {
            matches_wildcard(segment.as_bytes(), part.as_bytes()) && match_segments(rest, path_rest)
        }
        _ => false,
    }
}

fn matches_wildcard(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern.split_first(), text.split_first()) {
        (None, None) => true,
        (Some((b'*', rest)), _) => {
            matches_wildcard(rest, text)
                || (!text.is_empty() && matches_wildcard(pattern, &text[1..]))
        }
        (Some((b'?', rest)), Some((_, text_rest))) => matches_wildcard(rest, text_rest),
        (Some((expected, rest)), Some((actual, text_rest))) => {
            expected == actual && matches_wildcard(rest, text_rest)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envy::WorkspaceConfig;

    const FILE: &str = "envy.json";

    fn repository() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        dir
    }

    fn write_manifest(dir: &Path, members: Option<&[&str]>) -> Envy {
        fs::create_dir_all(dir).unwrap();
        let mut envy = Envy::new("P".into(), None).unwrap();
        envy.workspace = members.map(|members| WorkspaceConfig {
            members: members.iter().map(|m| m.to_string()).collect(),
        });
        envy.checksum = envy.compute_checksum().unwrap();
        envy.save(&dir.join(FILE)).unwrap();
        envy
    }

    #[test]
    fn member_patterns() {
        let p = Path::new;
        assert!(is_member("services/api", p("services/api")));
        assert!(is_member("./services/api/", p("services/api")));
        assert!(is_member("services/*", p("services/api")));
        assert!(!is_member("services/*", p("services/api/inner")));
        assert!(!is_member("services/*", p("apps/web")));
        assert!(is_member("services/a?i", p("services/api")));
        assert!(is_member("**/api", p("a/b/c/api")));
        assert!(is_member("**/api", p("api")));
        assert!(is_member("apps/**", p("apps/web/admin")));
        assert!(is_member("svc-*", p("svc-billing")));
        assert!(!is_member("svc-*", p("billing")));
        assert!(!is_member("*", p("")));
    }

    #[test]
    fn the_project_is_found_from_a_subdirectory() {
        let repo = repository();
        write_manifest(&repo.path().join("services/api"), None);
        let deep = repo.path().join("services/api/src/handlers");
        fs::create_dir_all(&deep).unwrap();

        assert_eq!(
            find_project_dir(&deep, FILE),
            Some(repo.path().join("services/api"))
        );
        assert_eq!(
            find_project_dir(&repo.path().join("services/api"), FILE),
            Some(repo.path().join("services/api"))
        );
        assert_eq!(find_project_dir(&repo.path().join("services"), FILE), None);
    }

    #[test]
    fn the_search_stops_at_the_repository_root() {
        let outer = tempfile::tempdir().unwrap();
        write_manifest(outer.path(), None);
        let repo = outer.path().join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();

        assert_eq!(find_project_dir(&repo, FILE), None);
        assert_eq!(repository_root(&repo), Some(repo.clone()));
    }

    #[test]
    fn a_listed_project_belongs_to_the_workspace() {
        let repo = repository();
        let root = write_manifest(repo.path(), Some(&["services/*"]));
        write_manifest(&repo.path().join("services/api"), None);
        write_manifest(&repo.path().join("tools/cli"), None);

        let (dir, found) = find_root(&repo.path().join("services/api"), FILE)
            .unwrap()
            .unwrap();
        assert_eq!(dir, repo.path());
        assert_eq!(found.id, root.id);

        assert!(
            find_root(&repo.path().join("tools/cli"), FILE)
                .unwrap()
                .is_none()
        );
        assert!(find_root(repo.path(), FILE).unwrap().is_none());

        let member = load_project(&repo.path().join("services/api"), FILE).unwrap();
        assert_eq!(member.parent.unwrap().id, root.id);
        let standalone = load_project(&repo.path().join("tools/cli"), FILE).unwrap();
        assert!(standalone.parent.is_none());
    }

    #[test]
    fn manifests_are_listed_without_hidden_and_dependency_folders() {
        let repo = repository();
        write_manifest(repo.path(), None);
        write_manifest(&repo.path().join("services/api"), None);
        write_manifest(&repo.path().join("services/api/node_modules/pkg"), None);
        write_manifest(&repo.path().join(".cache/x"), None);
        write_manifest(&repo.path().join("target/debug"), None);

        let found = find_manifests(repo.path(), FILE).unwrap();
        assert_eq!(
            found,
            vec![
                repo.path().join("envy.json"),
                repo.path().join("services/api/envy.json"),
            ]
        );
    }

    #[test]
    fn copied_manifests_are_detected() {
        let repo = repository();
        let api = write_manifest(&repo.path().join("services/api"), None);
        write_manifest(&repo.path().join("services/web"), None);
        fs::create_dir_all(repo.path().join("services/worker")).unwrap();
        fs::copy(
            repo.path().join("services/api/envy.json"),
            repo.path().join("services/worker/envy.json"),
        )
        .unwrap();

        let sharing = manifests_sharing_id(&repo.path().join("services/api"), FILE, &api).unwrap();
        assert_eq!(sharing, vec![repo.path().join("services/worker/envy.json")]);

        let ids: Vec<(PathBuf, String)> = find_manifests(repo.path(), FILE)
            .unwrap()
            .into_iter()
            .map(|path| {
                let id = Envy::load_from_file(&path).unwrap().id;
                (path, id)
            })
            .collect();
        let duplicated = duplicated_ids(&ids);
        assert_eq!(duplicated.len(), 1);
        assert_eq!(duplicated[&api.id].len(), 2);
    }
}
