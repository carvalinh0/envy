use std::io::Write;

use anyhow::{Result, anyhow, bail};

use crate::{
    cli::{Backend, LoginArgs},
    context::Context,
    identity,
    remote::{
        client::{Enrolment, enrol},
        transport::check_url,
    },
};

/// Records the project's server for this user and, with an invite or a root token, joins it
/// with a new identity. The backend only changes with `envy migrate --to remote`.
pub fn run(ctx: &Context, args: &LoginArgs, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    // The manifest comes from Git, where anyone who can push could point `server` at their
    // own host: a root token, which makes an admin, only goes to a URL typed by the operator.
    if args.root_token.is_some() && args.url.is_none() {
        bail!(
            "Give the server URL with a root token: `envy login <url> --root-token <token> --name <name>`."
        );
    }
    let url = args.url.clone().or(envy.server.clone()).ok_or_else(|| {
        anyhow!("Give the server URL (`envy login https://...`) or add \"server\" to the manifest.")
    })?;
    let url = check_url(&url)?;
    let remote = ctx.backends.remote;
    let transport = remote.connect(&url)?;
    remote.server_id(&*transport, &url)?;

    let credential = match (&args.invite, &args.root_token) {
        (Some(invite), _) => Some(Enrolment::Invite(invite.clone())),
        (_, Some(token)) => Some(Enrolment::RootToken(token.clone())),
        _ => None,
    };
    match credential {
        Some(credential) => {
            let name = args.name.clone().unwrap_or_default();
            let joined_with_invite = matches!(credential, Enrolment::Invite(_));
            let identity = enrol(&*transport, credential, &name)?;
            keep_identity(ctx, args, &url, &identity, out)?;
            report_enrolment(&identity, joined_with_invite, out)?;
        }
        None if identity::load(ctx.backends.identities, &url, ctx.config.identity.as_ref())?
            .is_none() =>
        {
            bail!(
                "This machine has no identity for {url}. Ask an admin for an invite (`envy user add`) and run `envy login {url} --invite <code> --name <name>`."
            );
        }
        None => {}
    }

    ctx.backends.choices.set_remote_url(&envy.id, Some(&url))?;
    ctx.record(&envy, "login", None, vec![url.clone()])?;
    if ctx.backends.current(&envy.id)? != Backend::Remote {
        writeln!(
            out,
            "This project will use {url} once you run `envy migrate --to remote`."
        )?;
    }
    Ok(())
}

fn keep_identity(
    ctx: &Context,
    args: &LoginArgs,
    url: &str,
    identity: &identity::Identity,
    out: &mut dyn Write,
) -> Result<()> {
    if !args.print_identity {
        return identity::save(ctx.backends.identities, url, identity);
    }
    writeln!(
        out,
        "Identity (shown only once; store it as the ENVY_IDENTITY secret of the machine that uses it):"
    )?;
    writeln!(out, "{}", identity.export().expose_secret())?;
    Ok(())
}

fn report_enrolment(
    identity: &identity::Identity,
    invited: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let fingerprint = identity.public().fingerprint();
    writeln!(
        out,
        "Joined as '{}'. Fingerprint: {fingerprint}",
        identity.name
    )?;
    if invited {
        writeln!(
            out,
            "Send this fingerprint to an admin through another channel; they run `envy user approve {} --fingerprint {fingerprint} --env <env>`.",
            identity.name
        )?;
    }
    Ok(())
}

/// Forgets the server of the project on this machine; the server keeps the values.
pub fn logout(ctx: &Context, out: &mut dyn Write) -> Result<()> {
    let envy = ctx.load_envy()?;
    let choices = ctx.backends.choices;
    if choices.chosen(&envy.id)? == Some(Backend::Remote) {
        choices.choose(&envy.id, None)?;
    }
    choices.set_remote_url(&envy.id, None)?;
    ctx.record(&envy, "logout", None, Vec::new())?;
    writeln!(
        out,
        "This project no longer uses a server on this machine; it is back on the keyring. The server keeps its values."
    )?;
    Ok(())
}
