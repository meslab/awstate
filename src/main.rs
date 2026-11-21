use anyhow::Result;
use clap::Parser;

use awstate::cli::{Args, OutputFormat};

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

    let (fail_on, format) = (args.fail_on, args.format);
    let snapshot = awstate::run(args).await?;
    match format {
        OutputFormat::Text => print!("{}", snapshot.report.to_text()),
        OutputFormat::Json => println!("{}", snapshot.report.to_json()?),
    }
    if let (Some(threshold), Some(worst)) = (fail_on, snapshot.worst)
        && worst >= threshold
    {
        std::process::exit(2);
    }
    Ok(())
}
