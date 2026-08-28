use std::{env, error::Error, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("generate_ephemeral_pki: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut arguments = env::args_os().skip(1);
    let directory = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: generate_ephemeral_pki <directory> <server-name>")?,
    );
    let server_name = arguments
        .next()
        .ok_or("usage: generate_ephemeral_pki <directory> <server-name>")?
        .into_string()
        .map_err(|_| "server name must be valid Unicode")?;
    if arguments.next().is_some() {
        return Err("usage: generate_ephemeral_pki <directory> <server-name>".into());
    }
    rustgo_e2e::generate_ephemeral_pki(&directory, &server_name)?;
    Ok(())
}
