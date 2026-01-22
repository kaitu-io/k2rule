//! k2rule-gen: CLI tool for generating binary rule files from Clash YAML configs.

use clap::{Parser, Subcommand};
use k2rule::binary::{BinaryRuleWriter, IntermediateRules};
use k2rule::converter::ClashConverter;
use k2rule::Target;
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

    /// Download and generate rules from remote URLs
    Download {
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
        Commands::Download {
            output_dir,
            verbose,
        } => {
            if let Err(e) = download_and_generate(&output_dir, verbose) {
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
    let converter = ClashConverter::new();
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

    if verbose {
        println!("Writing output file: {:?} ({} bytes)", output, binary_data.len());
    }

    let mut file = fs::File::create(output)?;
    file.write_all(&binary_data)?;

    println!("Successfully converted {:?} -> {:?}", input, output);
    Ok(())
}

fn generate_all(output_dir: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let clash_rules_dir = PathBuf::from("clash_rules");
    if !clash_rules_dir.exists() {
        return Err("clash_rules directory not found".into());
    }

    // Generate cn_blacklist.bin
    let blacklist_path = clash_rules_dir.join("cn_blacklist.yml");
    if blacklist_path.exists() {
        let output_path = output_dir.join("cn_blacklist.bin");
        convert_file(&blacklist_path, &output_path, verbose)?;
    }

    // Generate cn_whitelist.bin
    let whitelist_path = clash_rules_dir.join("cn_whitelist.yml");
    if whitelist_path.exists() {
        let output_path = output_dir.join("cn_whitelist.bin");
        convert_file(&whitelist_path, &output_path, verbose)?;
    }

    println!("All rule files generated in {:?}", output_dir);
    Ok(())
}

fn download_and_generate(output_dir: &PathBuf, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    // Define rule providers to download
    let providers = vec![
        (
            "reject",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
            Target::Reject,
        ),
        (
            "proxy",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt",
            Target::Proxy,
        ),
        (
            "direct",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
            Target::Direct,
        ),
        (
            "private",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt",
            Target::Direct,
        ),
        (
            "gfw",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
            Target::Proxy,
        ),
        (
            "greatfire",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt",
            Target::Proxy,
        ),
        (
            "tld-not-cn",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt",
            Target::Proxy,
        ),
        (
            "cncidr",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt",
            Target::Direct,
        ),
        (
            "lancidr",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/lancidr.txt",
            Target::Direct,
        ),
    ];

    let mut all_rules = IntermediateRules::new();

    for (name, url, target) in &providers {
        if verbose {
            println!("Downloading {}: {}", name, url);
        }

        match client.get(*url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    let content = response.text()?;
                    parse_provider_content(&mut all_rules, &content, *target, name);
                    if verbose {
                        println!("  Downloaded {} rules", content.lines().count());
                    }
                } else {
                    eprintln!("  Warning: Failed to download {}: {}", name, response.status());
                }
            }
            Err(e) => {
                eprintln!("  Warning: Failed to download {}: {}", name, e);
            }
        }
    }

    // Set fallback to PROXY (cn_blacklist mode)
    all_rules.set_fallback(Target::Direct);

    if verbose {
        println!(
            "\nTotal rules: {} domains, {} CIDRs, {} GeoIP",
            all_rules.exact_domains.len() + all_rules.suffix_domains.len(),
            all_rules.v4_cidrs.len() + all_rules.v6_cidrs.len(),
            all_rules.geoip_countries.len()
        );
    }

    // Write combined binary file
    let mut writer = BinaryRuleWriter::new();
    let binary_data = writer.write(&all_rules)?;

    let output_path = output_dir.join("rules.bin");
    let mut file = fs::File::create(&output_path)?;
    file.write_all(&binary_data)?;

    println!("Generated {:?} ({} bytes)", output_path, binary_data.len());
    Ok(())
}

fn parse_provider_content(rules: &mut IntermediateRules, content: &str, target: Target, name: &str) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Check if it's a CIDR rule
        if name.contains("cidr") {
            if let Some((network, prefix_len)) = parse_cidr(line) {
                match network {
                    CidrNetwork::V4(n) => rules.add_v4_cidr(n, prefix_len, target),
                    CidrNetwork::V6(n) => rules.add_v6_cidr(n, prefix_len, target),
                }
            }
        } else {
            // Domain rule
            // Convert +. prefix to . prefix
            let domain = if line.starts_with("+.") {
                format!(".{}", &line[2..])
            } else {
                line.to_string()
            };
            rules.add_domain(&domain, target);
        }
    }
}

enum CidrNetwork {
    V4(u32),
    V6([u8; 16]),
}

fn parse_cidr(cidr: &str) -> Option<(CidrNetwork, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix_len: u8 = parts[1].parse().ok()?;

    if let Ok(addr) = parts[0].parse::<std::net::Ipv4Addr>() {
        return Some((CidrNetwork::V4(u32::from(addr)), prefix_len));
    }

    if let Ok(addr) = parts[0].parse::<std::net::Ipv6Addr>() {
        return Some((CidrNetwork::V6(addr.octets()), prefix_len));
    }

    None
}
