use anyhow::Result;
use clap::Parser;

use awstate::cli::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = match args.verbose {
        0 => "warn",
        1 => "awstate=info,warn",
        _ => "awstate=debug,info",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .init();

    let out = awstate::run(args).await?;
    println!("snapshot written to {}", out.display());
    println!("start with {}", out.join("summary.md").display());
    Ok(())
}
