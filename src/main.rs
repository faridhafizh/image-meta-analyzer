mod analyzer;
mod report;
mod security;
mod hash;

use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::process;

/// Image Metadata Security Analyzer
/// Extracts and audits EXIF/metadata from images for security and privacy risks.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Image file(s) to analyze (supports glob patterns)
    #[arg(required = true, value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Output report as JSON
    #[arg(short, long)]
    json: bool,

    /// Save report to a file instead of stdout
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Show only security warnings (suppress informational fields)
    #[arg(short, long)]
    warnings_only: bool,

    /// Verbose: print all raw EXIF tags
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    // Keep `--json` stdout machine-parseable; the banner would corrupt it.
    if !args.json {
        print_banner();
    }

    let mut all_reports = Vec::new();
    let mut had_error = false;

    for path in &args.files {
        match analyzer::analyze_image(path, args.verbose) {
            Ok(report) => {
                if args.json {
                    // Collect for JSON output
                    all_reports.push(report);
                } else {
                    report::print_report(&report, args.warnings_only);
                }
            }
            Err(e) => {
                eprintln!(
                    "{} Failed to analyze '{}': {}",
                    "ERROR".red().bold(),
                    path.display(),
                    e
                );
                had_error = true;
            }
        }
    }

    if args.json {
        let json_out = serde_json::to_string_pretty(&all_reports)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));

        if let Some(ref out_path) = args.output {
            if let Err(e) = std::fs::write(out_path, &json_out) {
                eprintln!("{} Could not write to '{}': {}", "ERROR".red().bold(), out_path.display(), e);
                process::exit(1);
            }
            println!("{} Report saved to '{}'", "✓".green().bold(), out_path.display());
        } else {
            println!("{}", json_out);
        }
    }

    if had_error {
        process::exit(1);
    }
}

fn print_banner() {
    println!(
        "{}",
        r#"
╔══════════════════════════════════════════════════════════╗
║        IMAGE METADATA SECURITY ANALYZER  v1.0.0         ║
║          Detect privacy leaks hidden in images           ║
╚══════════════════════════════════════════════════════════╝"#
            .cyan()
            .bold()
    );
    println!();
}
