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

    let fail_on = args.fail_on;
    let snapshot = awstate::run(args).await?;
    println!("snapshot written to {}", snapshot.root.display());
    println!("start with {}", snapshot.root.join("summary.md").display());
    if let (Some(threshold), Some(worst)) = (fail_on, snapshot.worst)
        && worst >= threshold
    {
        std::process::exit(2);
    }
    Ok(())
}
