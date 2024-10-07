use chrono::Utc;
use clap::{ArgAction, Parser, Subcommand};
use log::{error, trace, LevelFilter, Log, Metadata, Record};
use sbomsleuth::license::Licenses;
use sbomsleuth::validate::parse_sbom;
use std::process::ExitCode;

#[derive(Subcommand)]
enum Commands {
    #[clap(about = "Generate quality report on SBOM.")]
    Report {
        #[arg(short, long)]
        file: String,
    },
    #[clap(about = "Generate license report on SBOM.")]
    License {
        #[arg(short, long)]
        file: String,
    },
    #[clap(about = "Validate SBOM.")]
    Validate {
        #[arg(short, long)]
        file: String,
    },
}

#[derive(Parser)]
#[command(name = "sbomsleuth")]
#[command(about = "CLI for investigating sboms.")]
struct Cli {
    #[arg(value_name = "FILE")]
    file: Option<String>,
    #[arg(short, long, action = ArgAction::Count, help = "Increase verbosity level. Use multiple times for more verbosity.")]
    verbosity: u8,
    #[arg(short = 'q', long)]
    quiet: bool,
    #[arg(
        short,
        long,
        value_name = "FORMAT",
        help = "Specify the output format (e.g., json, yaml, text)."
    )]
    format: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            Some(Commands::Validate { ref file }) => {
                self.validate(file.clone()).await?;
            }
            Some(Commands::License { ref file }) => {
                self.license(file.clone()).await?;
            }
            Some(Commands::Report { ref file }) => {
                self.report(file.clone()).await?;
            }
            None => {
                // if supplied just a file argument then run Report command by default
                if let Some(ref file) = self.file {
                    self.report(file.clone()).await?;
                } else {
                    // Print help message if no command or file is provided
                }
            }
        }
        Ok(())
    }

    async fn report(&self, file: String) -> anyhow::Result<()> {
        trace!("Generating Report on SBOM file: {}", file);

        if file.ends_with(".json") {
            match parse_sbom(&file) {
                Ok(parsed_sbom) => {
                    let license_instance = Licenses::default();
                    let report_instance = sbomsleuth::report::Report {
                        licenses: license_instance.run(&parsed_sbom).await.unwrap(),
                        ..Default::default()
                    };
                    let report = report_instance.run(parsed_sbom).unwrap();

                    println!("{}", (serde_json::to_string(&report).unwrap()));
                    Ok(())
                }
                Err(err) => Err(anyhow::anyhow!("{}", err)),
            }
        } else {
            error!("File '{}' is not a valid SBOM file.", file);
            Err(anyhow::anyhow!("Invalid SBOM file format"))
        }
    }

    async fn license(&self, file: String) -> anyhow::Result<()> {
        trace!("Generating license report on SBOM file: {}", file);

        if file.ends_with(".json") {
            match parse_sbom(&file) {
                Ok(parsed_sbom) => {
                    let license_instance = Licenses::default();
                    let licenses = license_instance.run(&parsed_sbom).await.unwrap();
                    println!("{}", (serde_json::to_string(&licenses).unwrap()));
                    Ok(())
                }
                Err(err) => Err(anyhow::anyhow!("{}", err)),
            }
        } else {
            error!("File '{}' is not a valid SBOM file.", file);
            Err(anyhow::anyhow!("Invalid SBOM file format"))
        }
    }

    async fn validate(&self, file: String) -> anyhow::Result<()> {
        trace!("Validating SBOM file: {}", file);

        if file.ends_with(".json") {
            match parse_sbom(&file) {
                Ok(parsed_sbom) => {
                    log::trace!("{:?}", parsed_sbom);
                    Ok(())
                }
                Err(err) => Err(anyhow::anyhow!("{}", err)),
            }
        } else {
            error!("File '{}' is not a valid SBOM file.", file);
            Err(anyhow::anyhow!("Invalid SBOM file format"))
        }
    }
}

struct CustomLogger;

impl Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= LevelFilter::Trace
    }

    fn log(&self, record: &Record) {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let level = record.level();
        let target = record.target();
        let message = record.args();

        // Create the log message
        let log_message = if level == LevelFilter::Error || level == LevelFilter::Trace {
            format!("[{now} {level} {target}] {message}")
        } else {
            format!("{message}")
        };

        println!("{}", log_message);
    }

    fn flush(&self) {}
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        LevelFilter::Error // If quiet is set, only show errors
    } else {
        match cli.verbosity {
            0 => LevelFilter::Error,
            1 => LevelFilter::Warn,
            2 => LevelFilter::Info,
            3 => LevelFilter::Debug,
            _ => LevelFilter::Trace, // More than 3 'v's
        }
    };

    // Set the custom logger
    log::set_boxed_logger(Box::new(CustomLogger))
        .map(|()| log::set_max_level(log_level))
        .unwrap();

    if let Err(err) = cli.run().await {
        error!("Failed to execute: {err}");
        for (n, cause) in err.chain().enumerate().skip(1) {
            error!("  {n}: {cause}");
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_command() {
        let mut cmd = Command::cargo_bin("sbomsleuth").unwrap();
        cmd.arg("../../etc/test-data/spdx/simple.json")
            .assert()
            .success();
    }

    #[test]
    fn test_validate_sbom() {
        let mut cmd = Command::cargo_bin("sbomsleuth").unwrap();
        cmd.arg("validate")
            .arg("--file")
            .arg("../../etc/test-data/spdx/simple.json")
            .assert()
            .success();
    }

    #[test]
    fn test_invalid_validate_sbom() {
        let mut cmd = Command::cargo_bin("sbomsleuth").unwrap();
        cmd.arg("validate")
            .arg("--file")
            .arg("../../etc/test-data/spdx/invalid.json")
            .assert()
            .stdout(predicate::str::contains("missing field `SPDXID`"))
            .failure();
    }

    #[test]
    fn test_help_banner() {
        let mut cmd = Command::cargo_bin("sbomsleuth").unwrap();
        cmd.arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "Usage: sbomsleuth [OPTIONS] [FILE] [COMMAND]",
            ));
    }
}
