//! Process entry point for the health-only pagebin server.
#![doc = include_str!("../README.md")]
#![deny(unsafe_code, missing_docs, rustdoc::broken_intra_doc_links)]

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match pagebin::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pagebin: {error}");
            ExitCode::FAILURE
        }
    }
}
