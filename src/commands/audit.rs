use std::io::Write;

use anyhow::{Result, bail};

use crate::{audit::AuditEvent, context::Context};

pub fn run(ctx: &Context, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
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
