//! Professional benchmarks for k2rule query performance.
//!
//! Run with: cargo bench
//!
//! This benchmark suite measures:
//! - Query throughput (queries per second)
//! - Cache hit vs miss performance
//! - Memory usage
//! - Scalability with different rule set sizes

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use k2rule::binary::{BinaryRuleWriter, CachedBinaryReader, CachedReaderConfig, IntermediateRules};
use k2rule::Target;

/// Generate test rules with specified counts.
fn generate_rules(
    exact_domain_count: usize,
    suffix_domain_count: usize,
    cidr_count: usize,
) -> Vec<u8> {
    let mut rules = IntermediateRules::new();

    // Add exact domains
    for i in 0..exact_domain_count {
        let target = match i % 3 {
            0 => Target::Direct,
            1 => Target::Proxy,
            _ => Target::Reject,
        };
        rules.add_domain(&format!("domain{}.example.com", i), target);
    }

    // Add suffix domains
    for i in 0..suffix_domain_count {
        let target = match i % 3 {
            0 => Target::Direct,
            1 => Target::Proxy,
            _ => Target::Reject,
        };
        rules.add_domain(&format!(".suffix{}.com", i), target);
    }

    // Add IPv4 CIDRs
    for i in 0..cidr_count.min(250) {
        let target = match i % 3 {
            0 => Target::Direct,
            1 => Target::Proxy,
            _ => Target::Reject,
        };
        rules.add_v4_cidr(u32::from_be_bytes([i as u8, 0, 0, 0]), 8, target);
    }

    let mut writer = BinaryRuleWriter::new();
    writer.write(&rules).unwrap()
}

/// Generate test queries - mix of hits and misses.
fn generate_queries(count: usize, hit_ratio: f64) -> Vec<String> {
    let mut queries = Vec::with_capacity(count);
    let hits = (count as f64 * hit_ratio) as usize;

    // Queries that will hit
    for i in 0..hits {
        if i % 2 == 0 {
            queries.push(format!("domain{}.example.com", i % 1000));
        } else {
            queries.push(format!("sub.suffix{}.com", i % 1000));
        }
    }

    // Queries that will miss
    for i in hits..count {
        queries.push(format!("unknown{}.nonexistent.org", i));
    }

    queries
}

/// Benchmark domain query throughput without cache.
fn bench_domain_query_no_cache(c: &mut Criterion) {
    let data = generate_rules(10_000, 5_000, 100);
    let config = CachedReaderConfig::no_cache();
    let reader = CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

    let queries = generate_queries(1000, 0.8);

    let mut group = c.benchmark_group("domain_query_no_cache");
    group.throughput(Throughput::Elements(queries.len() as u64));

    group.bench_function("mixed_queries", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(reader.match_domain(query));
            }
        })
    });

    group.finish();
}

/// Benchmark domain query throughput with cache.
fn bench_domain_query_with_cache(c: &mut Criterion) {
    let data = generate_rules(10_000, 5_000, 100);
    let config = CachedReaderConfig::with_capacity(10_000);
    let reader = CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

    let queries = generate_queries(1000, 0.8);

    // Warm up cache
    for query in &queries {
        let _ = reader.match_domain(query);
    }

    let mut group = c.benchmark_group("domain_query_with_cache");
    group.throughput(Throughput::Elements(queries.len() as u64));

    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(reader.match_domain(query));
            }
        })
    });

    group.finish();
}

/// Benchmark cache miss vs hit performance.
fn bench_cache_performance(c: &mut Criterion) {
    let data = generate_rules(10_000, 5_000, 100);
    let config = CachedReaderConfig::with_capacity(10_000);
    let reader = CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

    let mut group = c.benchmark_group("cache_performance");

    // Single query - cache miss
    group.bench_function("single_query_miss", |b| {
        b.iter_batched(
            || {
                reader.clear_cache();
                "domain500.example.com"
            },
            |query| black_box(reader.match_domain(query)),
            criterion::BatchSize::SmallInput,
        )
    });

    // Single query - cache hit (pre-warm)
    let _ = reader.match_domain("domain500.example.com");
    group.bench_function("single_query_hit", |b| {
        b.iter(|| black_box(reader.match_domain("domain500.example.com")))
    });

    group.finish();
}

/// Benchmark scalability with different rule set sizes.
fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability");

    for size in [100, 1_000, 10_000, 50_000].iter() {
        let data = generate_rules(*size, size / 2, 100);
        let config = CachedReaderConfig::no_cache();
        let reader =
            CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

        group.throughput(Throughput::Elements(100));
        group.bench_with_input(BenchmarkId::new("rules", size), size, |b, _| {
            let queries: Vec<_> = (0..100)
                .map(|i| format!("domain{}.example.com", i % size))
                .collect();
            b.iter(|| {
                for query in &queries {
                    black_box(reader.match_domain(query));
                }
            })
        });
    }

    group.finish();
}

/// Benchmark IP CIDR matching.
fn bench_ip_cidr(c: &mut Criterion) {
    let data = generate_rules(1_000, 500, 200);
    let config = CachedReaderConfig::no_cache();
    let reader = CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

    let ips: Vec<std::net::IpAddr> = (0..100)
        .map(|i| format!("{}.1.1.1", i % 200).parse().unwrap())
        .collect();

    let mut group = c.benchmark_group("ip_cidr");
    group.throughput(Throughput::Elements(ips.len() as u64));

    group.bench_function("ipv4_lookup", |b| {
        b.iter(|| {
            for ip in &ips {
                black_box(reader.match_ip(*ip));
            }
        })
    });

    group.finish();
}

/// Benchmark hot reload performance.
fn bench_hot_reload(c: &mut Criterion) {
    let data1 = generate_rules(10_000, 5_000, 100);
    let data2 = generate_rules(10_000, 5_000, 100);
    let config = CachedReaderConfig::with_capacity(10_000);
    let reader =
        CachedBinaryReader::from_bytes_with_config(data1.clone(), config.clone(), Target::Proxy)
            .unwrap();

    let mut group = c.benchmark_group("hot_reload");

    group.bench_function("reload_10k_rules", |b| {
        b.iter_batched(
            || data2.clone(),
            |data| {
                reader.reload_from_bytes(data).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// Benchmark suffix matching specifically (the complex path).
fn bench_suffix_matching(c: &mut Criterion) {
    let mut rules = IntermediateRules::new();

    // Add suffix rules at various depths
    rules.add_domain(".com", Target::Direct);
    rules.add_domain(".google.com", Target::Proxy);
    rules.add_domain(".youtube.com", Target::Proxy);
    rules.add_domain(".facebook.com", Target::Proxy);

    let mut writer = BinaryRuleWriter::new();
    let data = writer.write(&rules).unwrap();

    let config = CachedReaderConfig::no_cache();
    let reader = CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap();

    let mut group = c.benchmark_group("suffix_matching");

    // Deep subdomain chain
    group.bench_function("deep_subdomain", |b| {
        b.iter(|| black_box(reader.match_domain("a.b.c.d.e.f.google.com")))
    });

    // Direct suffix match
    group.bench_function("direct_suffix", |b| {
        b.iter(|| black_box(reader.match_domain("google.com")))
    });

    // TLD-only suffix
    group.bench_function("tld_suffix", |b| {
        b.iter(|| black_box(reader.match_domain("example.com")))
    });

    // No match (worst case - checks all suffixes)
    group.bench_function("no_match", |b| {
        b.iter(|| black_box(reader.match_domain("example.org")))
    });

    group.finish();
}

/// Benchmark memory usage estimation.
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_estimation");

    for size in [1_000, 10_000, 100_000].iter() {
        let data = generate_rules(*size, size / 2, 100);
        let data_len = data.len();

        group.bench_with_input(BenchmarkId::new("file_size", size), size, |b, _| {
            b.iter(|| {
                // Just measure the data size
                black_box(data_len)
            })
        });

        // Report file size
        println!(
            "Rule set with {} domains: {} bytes ({:.2} KB, {:.2} MB)",
            size,
            data_len,
            data_len as f64 / 1024.0,
            data_len as f64 / 1024.0 / 1024.0
        );
    }

    group.finish();
}

/// Benchmark concurrent access (simulated).
fn bench_concurrent_access(c: &mut Criterion) {
    use std::sync::Arc;

    let data = generate_rules(10_000, 5_000, 100);
    let config = CachedReaderConfig::with_capacity(10_000);
    let reader =
        Arc::new(CachedBinaryReader::from_bytes_with_config(data, config, Target::Proxy).unwrap());

    let queries = generate_queries(100, 0.8);

    let mut group = c.benchmark_group("concurrent_access");
    group.throughput(Throughput::Elements(queries.len() as u64));

    group.bench_function("single_thread", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(reader.match_domain(query));
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_domain_query_no_cache,
    bench_domain_query_with_cache,
    bench_cache_performance,
    bench_scalability,
    bench_ip_cidr,
    bench_hot_reload,
    bench_suffix_matching,
    bench_memory_usage,
    bench_concurrent_access,
);

criterion_main!(benches);
