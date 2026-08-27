use std::path::PathBuf;

use clap::Parser;

/// Rustgo private-network client.
#[derive(Debug, Parser)]
#[command(name = "rustgoc")]
struct Cli {
    /// Path to the client configuration file.
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,
}

fn main() {
    let _cli = Cli::parse();
}
