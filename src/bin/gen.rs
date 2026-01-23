//! k2rule-gen: CLI tool for generating binary rule files from Clash YAML configs.

use clap::{Parser, Subcommand};
use flate2::write::GzEncoder;
use flate2::Compression;
use k2rule::binary::BinaryRuleWriter;
use k2rule::converter::{ClashConfig, ClashConverter};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "k2rule-gen")]
#[command(author = "Kaitu.io")]
#[command(version = "0.1.0")]
#[command(about = "Generate binary rule files from Clash YAML configs", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert Clash YAML config to binary format
    Convert {
        /// Input Clash YAML file
        #[arg(short, long)]
        input: PathBuf,

        /// Output binary file
        #[arg(short, long)]
        output: PathBuf,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate all rule sets from clash_rules directory
    GenerateAll {
        /// Output directory for binary files
        #[arg(short, long, default_value = "output")]
        output_dir: PathBuf,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Convert {
            input,
            output,
            verbose,
        } => {
            if let Err(e) = convert_file(&input, &output, verbose) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::GenerateAll {
            output_dir,
            verbose,
        } => {
            if let Err(e) = generate_all(&output_dir, verbose) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn convert_file(
    input: &PathBuf,
    output: &PathBuf,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if verbose {
        println!("Reading input file: {:?}", input);
    }

    let yaml_content = fs::read_to_string(input)?;

    // Parse config first to get rule-providers
    let config: ClashConfig = serde_yaml::from_str(&yaml_content)?;

    // Create HTTP client for downloading rule providers
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut converter = ClashConverter::new();

    // Download and load each rule provider
    for (name, provider) in &config.rule_providers {
        if let Some(url) = &provider.url {
            if verbose {
                println!("  Downloading provider '{}': {}", name, url);
            }

            match client.get(url).send() {
                Ok(response) => {
                    if response.status().is_success() {
                        let content = response.text()?;
                        let lines = parse_provider_payload(&content);

                        if verbose {
                            println!("    Loaded {} rules", lines.len());
                        }

                        converter.set_provider_rules(name, lines);
                    } else {
                        eprintln!(
                            "  Warning: Failed to download {}: {}",
                            name,
                            response.status()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  Warning: Failed to download {}: {}", name, e);
                }
            }
        }
    }

    let rules = converter.convert(&yaml_content)?;

    if verbose {
        println!(
            "Parsed rules: {} domains, {} CIDRs, {} GeoIP, {} IPs",
            rules.exact_domains.len() + rules.suffix_domains.len(),
            rules.v4_cidrs.len() + rules.v6_cidrs.len(),
            rules.geoip_countries.len(),
            rules.exact_v4_ips.len() + rules.exact_v6_ips.len()
        );
    }

    let mut writer = BinaryRuleWriter::new();
    let binary_data = writer.write(&rules)?;

    // Check if output should be gzip compressed
    let is_gzip = output
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e == "gz")
        .unwrap_or(false);

    if is_gzip {
        if verbose {
            println!(
                "Writing gzip compressed output file: {:?} ({} bytes uncompressed)",
                output,
                binary_data.len()
            );
        }
        let file = fs::File::create(output)?;
        let mut encoder = GzEncoder::new(file, Compression::best());
        encoder.write_all(&binary_data)?;
        encoder.finish()?;
    } else {
        if verbose {
            println!(
                "Writing output file: {:?} ({} bytes)",
                output,
                binary_data.len()
            );
        }
        let mut file = fs::File::create(output)?;
        file.write_all(&binary_data)?;
    }

    println!("Successfully converted {:?} -> {:?}", input, output);
    Ok(())
}

fn generate_all(output_dir: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let clash_rules_dir = PathBuf::from("clash_rules");
    if !clash_rules_dir.exists() {
        return Err("clash_rules directory not found".into());
    }

    // Generate cn_blacklist.k2r.gz (gzip compressed)
    let blacklist_path = clash_rules_dir.join("cn_blacklist.yml");
    if blacklist_path.exists() {
        let output_path = output_dir.join("cn_blacklist.k2r.gz");
        convert_file(&blacklist_path, &output_path, verbose)?;
    }

    // Generate cn_whitelist.k2r.gz (gzip compressed)
    let whitelist_path = clash_rules_dir.join("cn_whitelist.yml");
    if whitelist_path.exists() {
        let output_path = output_dir.join("cn_whitelist.k2r.gz");
        convert_file(&whitelist_path, &output_path, verbose)?;
    }

    println!("All rule files generated in {:?}", output_dir);
    Ok(())
}

/// Parse provider payload content (handles both YAML payload format and plain text).
fn parse_provider_payload(content: &str) -> Vec<String> {
    let trimmed = content.trim();

    // Check if it's YAML payload format
    if trimmed.starts_with("payload:") {
        // Parse YAML format: payload:\n  - 'rule1'\n  - 'rule2'
        trimmed
            .lines()
            .skip(1) // Skip "payload:" line
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                // Remove "- " prefix and quotes
                let rule = line.strip_prefix('-').map(|s| s.trim()).unwrap_or(line);
                let rule = rule
                    .trim_start_matches('\'')
                    .trim_end_matches('\'')
                    .trim_start_matches('"')
                    .trim_end_matches('"');
                if rule.is_empty() {
                    None
                } else {
                    Some(rule.to_string())
                }
            })
            .collect()
    } else {
        // Plain text format: one rule per line
        trimmed
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .map(|l| l.trim().to_string())
            .collect()
    }
}
