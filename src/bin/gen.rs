//! k2rule-gen: CLI tool for generating binary rule files from Clash YAML configs.

use clap::{Parser, Subcommand};
use flate2::write::GzEncoder;
use flate2::Compression;
use k2rule::binary::{BinaryRuleWriter, IntermediateRules};
use k2rule::converter::{ClashConfig, ClashConverter};
use k2rule::Target;
use serde::Deserialize;
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

    /// Generate porn domain list from Bon-Appetit/porn-domains repo
    GeneratePorn {
        /// Output file (supports .k2r or .k2r.gz)
        #[arg(short, long, default_value = "output/porn_domains.k2r.gz")]
        output: PathBuf,

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
        Commands::GeneratePorn { output, verbose } => {
            if let Err(e) = generate_porn(&output, verbose) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn convert_file(input: &PathBuf, output: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
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
                        eprintln!("  Warning: Failed to download {}: {}", name, response.status());
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
            println!("Writing output file: {:?} ({} bytes)", output, binary_data.len());
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

/// Meta JSON structure from porn-domains repo
#[derive(Debug, Deserialize)]
struct PornDomainsMeta {
    blocklist: PornDomainsFile,
    #[allow(dead_code)]
    allowlist: PornDomainsFile,
}

#[derive(Debug, Deserialize)]
struct PornDomainsFile {
    name: String,
    updated: String,
    lines: u64,
    #[allow(dead_code)]
    size: u64,
}

const PORN_DOMAINS_META_URL: &str =
    "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/main/meta.json";
const PORN_DOMAINS_BASE_URL: &str =
    "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/main/";

fn generate_porn(output: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure output directory exists
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }

    // Create HTTP client
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 minutes timeout for large file
        .build()?;

    // Step 1: Fetch meta.json to get the blocklist filename
    if verbose {
        println!("Fetching meta.json from porn-domains repo...");
    }

    let meta_response = client.get(PORN_DOMAINS_META_URL).send()?;
    if !meta_response.status().is_success() {
        return Err(format!("Failed to fetch meta.json: {}", meta_response.status()).into());
    }

    let meta: PornDomainsMeta = meta_response.json()?;

    if verbose {
        println!("  Blocklist file: {}", meta.blocklist.name);
        println!("  Updated: {}", meta.blocklist.updated);
        println!("  Lines: {}", meta.blocklist.lines);
    }

    // Step 2: Fetch the blocklist file
    let blocklist_url = format!("{}{}", PORN_DOMAINS_BASE_URL, meta.blocklist.name);
    if verbose {
        println!("Downloading blocklist from: {}", blocklist_url);
    }

    let blocklist_response = client.get(&blocklist_url).send()?;
    if !blocklist_response.status().is_success() {
        return Err(format!("Failed to fetch blocklist: {}", blocklist_response.status()).into());
    }

    let blocklist_content = blocklist_response.text()?;

    // Step 3: Parse domains
    let domains: Vec<&str> = blocklist_content
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .collect();

    if verbose {
        println!("Parsed {} domains", domains.len());
    }

    // Step 4: Build IntermediateRules
    let mut rules = IntermediateRules::new();

    for domain in &domains {
        // Add as suffix match to catch subdomains too
        // The format in porn-domains is just domain names
        rules.add_domain(&format!(".{}", domain), Target::Reject);
        // Also add exact match
        rules.add_domain(domain, Target::Reject);
    }

    if verbose {
        println!(
            "Created rules: {} exact + {} suffix domains",
            rules.exact_domains.len(),
            rules.suffix_domains.len()
        );
    }

    // Step 5: Write binary file
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
                "Writing gzip compressed output: {:?} ({} bytes uncompressed)",
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
            println!("Writing output: {:?} ({} bytes)", output, binary_data.len());
        }
        let mut file = fs::File::create(output)?;
        file.write_all(&binary_data)?;
    }

    // Write version file (source timestamp)
    let version_path = output.with_extension("version");
    fs::write(&version_path, &meta.blocklist.updated)?;

    println!(
        "Successfully generated porn domain list: {:?} ({} domains, source: {})",
        output,
        domains.len(),
        meta.blocklist.updated
    );

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
                let rule = line
                    .strip_prefix('-')
                    .map(|s| s.trim())
                    .unwrap_or(line);
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
