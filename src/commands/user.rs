use std::io::Write;

use anyhow::Result;

use crate::{
    cli::{UserAction, UserArgs},
    context::Context,
    envy::Envy,
    remote::protocol::{ALL_ENVIRONMENTS, MemberStatus},
};

pub fn run(ctx: &Context, args: &UserArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    match &args.action {
        UserAction::Add { name, admin } => add(ctx, &envy, name, *admin, out),
        UserAction::Approve {
            name,
            fingerprint,
            environments,
            write,
        } => approve(ctx, &envy, name, fingerprint, environments, *write, out),
        UserAction::Rm { name } => remove(ctx, &envy, name, out),
        UserAction::List => list(ctx, &envy, out),
    }
}

fn add(ctx: &Context, envy: &Envy, name: &str, admin: bool, out: &mut dyn Write) -> Result<()> {
    let remote = ctx.backends.remote;
    let invite = remote.add_member(&envy.id, name, admin)?;
    let url = remote.url(&envy.id)?;
    ctx.record(envy, "user-add", None, vec![name.into()])?;
    writeln!(
        out,
        "Invite for '{name}' (shown only once, valid 24 hours; send it through a private channel):"
    )?;
    writeln!(out, "{}", invite.invite)?;
    writeln!(
        out,
        "They run: envy login {url} --invite <invite> --name {name}"
    )?;
    Ok(())
}

fn approve(
    ctx: &Context,
    envy: &Envy,
    name: &str,
    fingerprint: &str,
    environments: &[String],
    write: bool,
    out: &mut dyn Write,
) -> Result<()> {
    for env in environments.iter().filter(|e| *e != ALL_ENVIRONMENTS) {
        ctx.target_environment(envy, Some(env))?;
    }
    ctx.backends
        .remote
        .approve(&envy.id, name, fingerprint, environments, write)?;
    ctx.record(envy, "user-approve", None, vec![name.into()])?;
    writeln!(
        out,
        "'{name}' is active and can {} {} of this project.",
        if write { "read and write" } else { "read" },
        environments.join(", ")
    )?;
    Ok(())
}

/// Removes the member, then replaces the key of every environment it could read that this
/// machine can rekey. What it already read can't be taken back, so the values must change.
fn remove(ctx: &Context, envy: &Envy, name: &str, out: &mut dyn Write) -> Result<()> {
    let remote = ctx.backends.remote;
    let lost = remote.remove_member(&envy.id, name)?;
    ctx.record(envy, "user-rm", None, vec![name.into()])?;
    writeln!(out, "'{name}' was removed and its sessions revoked.")?;

    let mut rotate = Vec::new();
    for (project, env) in lost {
        let envs = match env.as_str() {
            ALL_ENVIRONMENTS => remote.environments(&project).unwrap_or_default(),
            _ => vec![env],
        };
        for env in envs {
            match remote.rekey(&project, &env) {
                Ok(_) => writeln!(out, "  new key for '{env}' of project {project}")?,
                Err(err) => writeln!(
                    out,
                    "  could not rekey '{env}' of project {project} ({err}); someone with write access must run `envy vault rekey {env}` there"
                )?,
            }
            rotate.push(format!("{env} ({project})"));
        }
    }
    if !rotate.is_empty() {
        writeln!(
            out,
            "'{name}' could read these environments: change their values too, the old ones may have been copied: {}",
            rotate.join(", ")
        )?;
    }
    Ok(())
}

fn list(ctx: &Context, envy: &Envy, out: &mut dyn Write) -> Result<()> {
    let members = ctx.backends.remote.members(&envy.id)?;
    let width = members
        .iter()
        .map(|m| m.name.len())
        .chain([4])
        .max()
        .unwrap_or(4);
    writeln!(out, "{:<width$}  {:<8}  FINGERPRINT", "NAME", "STATUS")?;
    for member in members {
        let status = match member.status {
            MemberStatus::Invited => "invited",
            MemberStatus::Pending => "pending",
            MemberStatus::Active if member.admin => "admin",
            MemberStatus::Active => "active",
            MemberStatus::Removed => "removed",
        };
        let fingerprint = member
            .keys
            .and_then(|keys| keys.decode())
            .map(|keys| keys.fingerprint())
            .unwrap_or_else(|| "-".into());
        writeln!(out, "{:<width$}  {status:<8}  {fingerprint}", member.name)?;
    }
    Ok(())
}
