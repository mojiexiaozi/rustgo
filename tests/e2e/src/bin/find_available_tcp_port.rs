use std::{net::TcpListener, process::ExitCode};

fn main() -> ExitCode {
    match TcpListener::bind(("127.0.0.1", 0)).and_then(|listener| listener.local_addr()) {
        Ok(address) => {
            println!("{}", address.port());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("find_available_tcp_port: {error}");
            ExitCode::FAILURE
        }
    }
}
