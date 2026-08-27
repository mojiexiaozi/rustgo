use std::path::PathBuf;

use clap::Parser;

/// Rustgo public relay server.
#[derive(Debug, Parser)]
#[command(name = "rustgos")]
struct Cli {
    /// Path to the server configuration file.
    #[arg(short, long, default_value = "server.toml")]
    config: PathBuf,
}

fn main() {
    let _cli = Cli::parse();
}
