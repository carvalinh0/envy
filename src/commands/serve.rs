use std::io::Write;

use anyhow::Result;

use crate::cli::ServeArgs;

/// Runs the server. The command exists in every build so the command line is the same
/// everywhere; only builds with the `server` feature on Linux can run it.
pub fn run(args: &ServeArgs, out: &mut dyn Write) -> Result<()> {
    #[cfg(all(feature = "server", target_os = "linux"))]
    {
        crate::server::http::serve(args, out)
    }
    #[cfg(not(all(feature = "server", target_os = "linux")))]
    {
        let _ = (args, out);
        anyhow::bail!(
            "This build of Envy has no server. On Linux run `cargo install dot-envy --features server`, or use the Docker image."
        )
    }
}
