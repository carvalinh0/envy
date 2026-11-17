use std::io::Write;

use anyhow::{Result, bail};

use crate::{
    audit::AuditEvent, cli::AuditArgs, context::Context, envy::Envy, remote::protocol::AuditEntry,
};

pub fn run(ctx: &Context, args: &AuditArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    if args.server {
        return server(ctx, &envy, out);
    }
    let Some(trail) = ctx.audit.read(&envy.id)? else {
        bail!(
            "Auditing is disabled: Envy found no folder for its data (set HOME, or LOCALAPPDATA on Windows)."
        );
    };

    for event in &trail.events {
        writeln!(out, "{}", line(event))?;
    }
    if let Some(number) = trail.broken_at {
        bail!(
            "The audit log was modified at or after line {number}: the events from there on can't be trusted."
        );
    }
    writeln!(out, "{} event(s); the log is intact.", trail.events.len())?;
    Ok(())
}

/// The server's own log of this project: who read or changed which environments.
fn server(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    let entries = ctx.backends.remote.audit(&envy.id, true)?;
    for entry in &entries {
        writeln!(out, "{}", server_line(entry))?;
    }
    writeln!(out, "{} event(s) on the server.", entries.len())?;
    Ok(())
}

fn server_line(entry: &AuditEntry) -> String {
    let at = chrono::DateTime::from_timestamp(entry.at, 0)
        .map(|at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default();
    let mut text = format!("{at}  {}  {}", entry.member, entry.action);
    if !entry.envs.is_empty() {
        text.push_str(&format!("  {}", entry.envs.join(", ")));
    }
    text
}

fn line(event: &AuditEvent) -> String {
    let mut text = format!(
        "{}  {}  {}",
        event.at.format("%Y-%m-%d %H:%M:%S UTC"),
        event.user,
        event.action
    );
    if let Some(environment) = &event.environment {
        text.push_str(&format!("  [{environment}]"));
    }
    if !event.keys.is_empty() {
        text.push_str(&format!("  {}", event.keys.join(", ")));
    }
    text
}
