use std::{
    fs::{self, OpenOptions},
    io::IsTerminal,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use futures::future::join_all;
use reqwest::{Client, StatusCode};
use tokio::sync::watch;
use tracing::{error, info, warn};
use txwatch_config::{AppConfig, WebhookDestination, WebhookFormat, WebhookHeaders, REDACTED};
use txwatch_notifier::{
    build_client, destination_client, send_to_destination_simple, test_payload_with_network,
};

// ── CLI definition ────────────────────────────────────────────────────────────

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("TXWATCH_GIT_SHA"),
    " built ",
    env!("TXWATCH_BUILD_TIMESTAMP"),
    ")"
);

/// Default number of contracts polled concurrently. Shared by the
/// `watch --concurrency` flag and the config's `effective_concurrency()` so the
/// two defaults never disagree.
const DEFAULT_CONCURRENCY: usize = 8;

#[derive(Parser)]
#[command(
    name    = "txwatch",
    version = VERSION,
    about   = "Stellar Soroban contract monitor & webhook alert engine"
)]
struct Cli {
    /// Path to the TOML config file
    #[arg(short, long, env = "TXWATCH_CONFIG", default_value = "txwatch.toml")]
    config: PathBuf,

    /// Log output format: human-readable text or one JSON object per line
    #[arg(
        long,
        global = true,
        value_enum,
        env = "TXWATCH_LOG_FORMAT",
        default_value = "text"
    )]
    log_format: LogFormat,

    /// Override the Horizon base URL for every contract (e.g. a private Horizon instance)
    #[arg(long, global = true, value_parser = parse_horizon_url)]
    horizon_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// How `validate --check-webhooks` probes each destination.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WebhookCheckMode {
    /// HEAD request, falling back to OPTIONS on 405/501
    Head,
    /// Send a real `test: true` payload through the destination client
    Post,
}

/// Network names accepted by `test-webhook --network`. `public` and `pubnet`
/// are the names Stellar Expert uses for mainnet.
#[derive(Clone, Copy, ValueEnum)]
enum NetworkArg {
    Mainnet,
    #[value(alias = "public", alias = "pubnet")]
    MainnetAlias,
    Testnet,
    Futurenet,
}

impl NetworkArg {
    fn to_network(self) -> txwatch_config::Network {
        match self {
            NetworkArg::Mainnet | NetworkArg::MainnetAlias => txwatch_config::Network::Mainnet,
            NetworkArg::Testnet => txwatch_config::Network::Testnet,
            NetworkArg::Futurenet => txwatch_config::Network::Futurenet,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Start the polling engine (watches all contracts in the config)
    ///
    /// With --once, exit codes: 0 = every poll and webhook delivery succeeded, 1 = otherwise
    Watch {
        /// Do not actually send webhooks; only log matched rules
        #[arg(long)]
        dry_run: bool,

        /// Serve Prometheus /metrics (plus /healthz and /readyz) on this address, e.g. 127.0.0.1:9090
        #[cfg(feature = "metrics")]
        #[arg(long)]
        metrics_addr: Option<std::net::SocketAddr>,
        /// Run a single poll cycle, deliver alerts, save cursors and exit
        #[arg(long)]
        once: bool,

        /// Reload configuration when the config file or included files change
        #[arg(long, env = "TXWATCH_WATCH_CONFIG")]
        watch_config: bool,

        /// Maximum number of contracts polled concurrently
        #[arg(long)]
        concurrency: Option<usize>,
    },

    /// Parse and validate the config file, then print a summary
    ///
    /// Exit codes: 0 = valid config, 1 = invalid or missing config
    Validate {
        /// Probe each webhook URL. `head` (default) sends HEAD/OPTIONS; `post`
        /// sends a real `test: true` payload through the configured destination
        /// client (mTLS, custom headers, secrets).
        #[arg(
            long,
            value_enum,
            num_args = 0..=1,
            default_missing_value = "head",
            value_name = "MODE"
        )]
        check_webhooks: Option<WebhookCheckMode>,

        /// Verify that each contract exists on its configured Horizon network.
        #[arg(long)]
        check_horizon: bool,

        /// Output format. `json` prints the parsed config (secrets redacted) or the
        /// validation error as a single JSON object on stdout. Webhook and Horizon
        /// check results are included in the JSON output when the respective flags
        /// are also passed.
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },

    /// Send a test webhook payload to a URL and exit
    ///
    /// Exit codes: 0 = webhook delivered, 1 = delivery failed (unreachable or HTTP error)
    TestWebhook {
        /// The webhook URL to POST to
        #[arg(long)]
        url: Option<String>,

        /// Label to include in the test payload
        #[arg(long, default_value = "TxWatch Test")]
        label: String,

        /// Stellar network for the test payload
        #[arg(long, value_enum, default_value = "testnet")]
        network: NetworkArg,

        /// Horizon base URL for a custom network in the test payload
        #[arg(long, value_parser = parse_horizon_url, conflicts_with = "contract")]
        horizon_url: Option<String>,

        /// Explorer base URL for a custom network in the test payload
        #[arg(long, value_parser = parse_horizon_url)]
        explorer_url: Option<String>,

        /// Send to every destination of this configured contract instead of --url
        #[arg(long)]
        contract: Option<String>,

        /// Webhook secret (overrides the configured ones with --contract)
        #[arg(long)]
        secret: Option<String>,

        /// Body format for --url (see `txwatch test-webhook --help` for choices)
        #[arg(long, value_parser = parse_webhook_format, default_value = "txwatch")]
        /// Body format for --url: txwatch, slack, discord or pagerduty
        #[arg(
            long,
            value_parser = parse_webhook_format,
            default_value = "txwatch",
            conflicts_with = "contract"
        )]
        format: WebhookFormat,

        /// PagerDuty routing key for --url with --format pagerduty
        #[arg(long, conflicts_with = "contract")]
        routing_key: Option<String>,

        /// Template body for --url with --format template
        #[arg(long, conflicts_with = "template_file")]
        template: Option<String>,

        /// File containing the template body for --url with --format template
        #[arg(long, conflicts_with = "template")]
        template_file: Option<PathBuf>,

        /// Extra header for --url as "Name: value"; repeatable
        #[arg(long = "header", value_name = "NAME: VALUE", conflicts_with = "contract")]
        headers: Vec<String>,
    },

    /// Print the JSON Schema for the config file, the alert webhook payload or the batch body
    Schema {
        /// Print the schema for the alert webhook payload instead of the config
        #[arg(long, conflicts_with = "batch")]
        payload: bool,

        /// Print the schema for the batched webhook body ({"alerts": [...]})
        #[arg(long, conflicts_with = "payload")]
        batch: bool,
    },

    /// Print a shell completion script, e.g. `txwatch completions bash > /etc/bash_completion.d/txwatch`
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Print the txwatch(1) man page in roff format, e.g. `txwatch man > txwatch.1`
    Man,

    /// Write a starter config file for one contract
    ///
    /// Missing values are prompted for on stdin. The result is validated before
    /// it is written, and an existing file is never overwritten without --force.
    Init {
        /// Soroban contract address to watch (56 characters, starts with 'C')
        #[arg(long)]
        contract_id: Option<String>,

        /// Stellar network: mainnet, testnet, futurenet, or a custom horizon-url
        #[arg(long)]
        network: Option<String>,

        /// Override the Horizon base URL for this contract (implies a custom network)
        #[arg(long)]
        horizon_url: Option<String>,

        /// URL that receives webhook alerts
        #[arg(long)]
        webhook_url: Option<String>,

        /// Human-readable label for this contract (default: "My Contract")
        #[arg(long)]
        label: Option<String>,

        /// Alert rule preset to add; repeatable. Choices: any-transaction, failed,
        /// admin, large-transfer=<xlm>, high-fee=<stroops>, function=<name>
        #[arg(long = "rule", value_name = "PRESET")]
        rules: Vec<String>,

        /// Where to write the config
        #[arg(long, default_value = "txwatch.toml")]
        output: PathBuf,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,

        /// Never prompt; fail immediately if a required value is missing
        #[arg(long)]
        non_interactive: bool,
    },

    /// Evaluate a contract's rules against one historical transaction
    ///
    /// Prints the rules that matched and their webhook payloads. Nothing is sent
    /// unless --send is given. Exit codes: 0 = done, 1 = lookup or delivery failed
    Replay {
        /// Label of the configured contract whose rules to evaluate
        #[arg(long)]
        contract: String,

        /// Transaction hash to replay
        #[arg(long)]
        tx: String,

        /// Also deliver the resulting webhooks to the contract's webhook_url
        #[arg(long)]
        send: bool,

        /// Replay even when the transaction does not appear to involve the contract
        #[arg(long)]
        force: bool,
    },

    /// Inspect, set, or reset saved poll cursors
    Cursors {
        #[command(subcommand)]
        action: CursorsAction,

        /// Proceed even if another TxWatch instance holds the state lock.
        /// Edits made while `watch` is running may be overwritten by it.
        #[arg(long, global = true)]
        force: bool,
    },

    /// Remove saved cursor entries for contracts that are no longer configured
    ///
    /// Reloads keep cursors of removed contracts so re-adding one resumes where
    /// it left off; use this command to intentionally discard them.
    PruneCursors {
        /// Only report what would be removed, without writing the cursor file
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum CursorsAction {
    /// Show the current cursor for each configured contract
    Show,
    /// Set a contract's cursor to a specific paging token or ledger
    Set {
        /// Label of the contract to update
        #[arg(long)]
        contract: String,
        /// Paging token to set as the cursor
        #[arg(long, conflicts_with = "ledger")]
        cursor: Option<String>,
        /// Ledger sequence number to set as cursor start point
        #[arg(long, conflicts_with = "cursor")]
        ledger: Option<u64>,
    },
    /// Reset a contract's cursor to 'now' (re-processes from current ledger)
    Reset {
        /// Label of the contract to reset (omit to reset all)
        #[arg(long)]
        contract: Option<String>,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    match cli.command {
        Command::Validate {
            format: OutputFormat::Json,
            check_webhooks,
            check_horizon,
        } => {
            let cfg = match AppConfig::from_file(&required_config(&cli.config)?) {
                Ok(cfg) => cfg,
                Err(e) => {
                    let error = serde_json::json!({ "valid": false, "error": format!("{:#}", e) });
                    println!("{}", serde_json::to_string_pretty(&error)?);
                    std::process::exit(1);
                }
            };
            let mut summary = config_summary_json(&cfg);
            // #474: run every requested check, then print once and set the exit
            // code, so a failing webhook check never suppresses horizon results.
            let mut any_failed = false;

            // Optionally run webhook checks and embed results.
            if let Some(mode) = check_webhooks {
                let client = Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .context("failed to build HTTP client")?;
                let targets: Vec<(String, WebhookDestination)> = cfg
                    .contracts
                    .iter()
                    .flat_map(|c| {
                        c.destinations()
                            .into_iter()
                            .map(move |d| (c.label.clone(), d))
                    })
                    .collect();
                let results = join_all(targets.into_iter().map(|(label, destination)| {
                    let client = &client;
                    async move {
                        let result = check_webhook(client, &destination, mode).await;
                        (label, destination.url, result)
                    }
                }))
                .await;
                let mut webhook_checks = Vec::new();
                for (label, url, result) in results {
                    let (check, error) = match result {
                        Ok(check) => (check, None),
                        Err(e) => (
                            WebhookCheck {
                                reachable: false,
                                status: None,
                                ok: false,
                            },
                            Some(format!("{:#}", e)),
                        ),
                    };
                    if !check.ok {
                        any_failed = true;
                    }
                    let mut entry = serde_json::json!({
                        "contract": label,
                        "url": url,
                        "ok": check.ok,
                        "reachable": check.reachable,
                        "status": check.status,
                    });
                    if let Some(err) = error {
                        entry["error"] = serde_json::Value::from(err);
                    }
                    webhook_checks.push(entry);
                }
                summary["webhook_checks"] = serde_json::Value::from(webhook_checks);
            }

            // Optionally run Horizon checks and embed results.
            if check_horizon {
                let client = Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .context("failed to build HTTP client")?;
                let checks = join_all(
                    cfg.contracts
                        .iter()
                        .map(|c| check_horizon_contract(&client, c)),
                )
                .await;
                let horizon_checks: Vec<serde_json::Value> = checks
                    .into_iter()
                    .map(|check| {
                        // #473: share the pass/fail rule with the text output.
                        if !check_passed(&check) {
                            any_failed = true;
                        }
                        serde_json::json!({
                            "contract": check.contract,
                            "contract_id": check.contract_id,
                            "network": check.network,
                            "status": check.status,
                            "latest_ledger": check.latest_ledger,
                            "reachable": check.reachable,
                            "found": check.found,
                            "passphrase_ok": check.passphrase_ok,
                            "message": check.message,
                        })
                    })
                    .collect();
                summary["horizon_checks"] = serde_json::Value::from(horizon_checks);
            }

            if any_failed {
                summary["valid"] = serde_json::Value::Bool(false);
            }
            println!("{}", serde_json::to_string_pretty(&summary)?);
            if any_failed {
                std::process::exit(1);
            }
        }

        Command::Validate {
            check_webhooks,
            check_horizon,
            ..
        } => {
            let cfg = load_config(&cli)?;
            println!("Config is valid.");
            println!("  poll_interval_seconds : {}", cfg.poll_interval_seconds);
            println!("  contracts             : {}", cfg.contracts.len());
            // #410: report how many files each include pattern matched.
            if !cfg.include_matches.is_empty() {
                println!("  includes              :");
                for m in &cfg.include_matches {
                    println!(
                        "    {} -> {} file(s){}",
                        m.pattern,
                        m.files.len(),
                        if m.is_glob && m.files.is_empty() {
                            " (warning: glob matches no files)"
                        } else {
                            ""
                        }
                    );
                }
            }
            println!();
            for c in &cfg.contracts {
                println!(
                    "  [{network}] {label}{disabled}",
                    network = c.network.display_name(),
                    label = c.label,
                    disabled = if c.enabled { "" } else { " (disabled)" }
                );
                println!("    contract_id  : {}", c.contract_id);
                let destinations = c.destinations();
                println!("    webhooks     : {}", destinations.len());
                for destination in &destinations {
                    println!("      - {}", describe_destination(destination));
                }
                println!(
                    "    interval     : {}s{}",
                    c.effective_poll_interval(cfg.poll_interval_seconds),
                    if c.poll_interval_seconds.is_some() {
                        " (override)"
                    } else {
                        ""
                    }
                );
                println!("    rules        : {}", c.rules.len());
                for entry in &c.rules {
                    println!("      - {}{}", entry.rule.label(), if !entry.enabled { " (disabled)" } else { "" });
                }
                println!("    horizon      : {}", poll_base_url(c));
                match c.network.explorer_base_url() {
                    Some(explorer) => {
                        println!("    explorer     : {}/contract/{}", explorer, c.contract_id)
                    }
                    None => println!("    explorer     : none"),
                }
            }

            if let Some(mode) = check_webhooks {
                let client = Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .context("failed to build HTTP client")?;
                let targets: Vec<(String, WebhookDestination)> = cfg
                    .contracts
                    .iter()
                    .flat_map(|c| {
                        c.destinations()
                            .into_iter()
                            .map(move |d| (c.label.clone(), d))
                    })
                    .collect();
                let checks = join_all(targets.into_iter().map(|(label, destination)| {
                    let client = &client;
                    async move {
                        let result = check_webhook(client, &destination, mode).await;
                        (label, destination.url, result)
                    }
                }))
                .await;
                let mut failed = false;
                println!("Webhook checks:");
                for (label, url, result) in checks {
                    match result {
                        Ok(check) => {
                            if !check.ok {
                                failed = true;
                            }
                            println!(
                                "  {:<18} {:<20} {}",
                                label,
                                describe_webhook_check(&check),
                                url
                            )
                        }
                        Err(error) => {
                            failed = true;
                            println!("  {:<18} {:<20} {} ({})", label, "unreachable", url, error);
                        }
                    }
                }
                if failed {
                    return Err(anyhow::anyhow!("one or more webhook checks failed"));
                }
            }
            if check_horizon {
                let client = Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .context("failed to build HTTP client")?;
                let checks = join_all(
                    cfg.contracts
                        .iter()
                        .map(|c| check_horizon_contract(&client, c)),
                )
                .await;
                let mut failed = false;
                println!("Horizon checks:");
                for check in checks {
                    println!(
                        "  {:<18} {:<10} {:<20} latest ledger: {} — {}",
                        check.contract,
                        check.network,
                        check.status,
                        check
                            .latest_ledger
                            .map_or_else(|| "unknown".into(), |n| n.to_string()),
                        check.message
                    );
                    failed |= !check_passed(&check);
                }
                if failed {
                    return Err(anyhow::anyhow!("one or more Horizon checks failed"));
                }
            }
        }

        Command::TestWebhook {
            url,
            label,
            network,
            horizon_url,
            explorer_url,
            contract,
            secret,
            format,
            routing_key,
            template,
            template_file,
            headers,
        } => {
            let configured = contract
                .as_ref()
                .map(|wanted| {
                    let cfg = AppConfig::from_file(&required_config(&cli.config)?)?;
                    find_contract_by_label(&cfg, wanted)
                })
                .transpose()?;
            let (destinations, network, horizon, explorer) = if let Some(c) = configured {
                let mut destinations = c.destinations();
                if secret.is_some() {
                    for destination in &mut destinations {
                        destination.secret = secret.clone();
                    }
                }
                let horizon = poll_base_url(&c).to_string();
                let explorer = c.network.explorer_base_url().map(str::to_string);
                (destinations, c.network, horizon, explorer)
            } else {
                let selected = network.to_network();
                let horizon = horizon_url
                    .clone()
                    .unwrap_or_else(|| selected.horizon_base_url().to_string());
                let explorer = explorer_url
                    .clone()
                    .or_else(|| selected.explorer_base_url().map(str::to_string));
                let template_body = match (template, template_file) {
                    (Some(body), _) => Some(body),
                    (None, Some(path)) => Some(fs::read_to_string(&path).with_context(|| {
                        format!("failed to read template file '{}'", path.display())
                    })?),
                    (None, None) => None,
                };
                if format == WebhookFormat::Template && template_body.is_none() {
                    anyhow::bail!(
                        "--format template requires --template or --template-file to provide the body"
                    );
                }
                let destination = WebhookDestination {
                    url: url.ok_or_else(|| {
                        anyhow::anyhow!("--url is required unless --contract is provided")
                    })?,
                    secret,
                    format,
                    headers: parse_headers(&headers)?,
                    routing_key,
                    template: template_body,
                    ..Default::default()
                };
                destination.validate()?;
                (vec![destination], selected, horizon, explorer)
            };
            let client = build_client().context("failed to build HTTP client")?;

            // Try every destination, then fail if any of them failed.
            let mut failed = 0;
            for destination in &destinations {
                let payload = test_payload_with_network(
                    &label,
                    network.as_str(),
                    &horizon,
                    explorer.as_deref(),
                );
                info!(url = %destination.url, format = %destination.format, "sending test webhook");
                match send_to_destination_simple(&client, destination, &payload).await {
                    Ok(result) => println!(
                        "Test webhook delivered successfully to {} (format {}, status {}, attempts {})",
                        destination.url, destination.format, result.final_status, result.attempts
                    ),
                    Err(e) => {
                        failed += 1;
                        eprintln!("test webhook to '{}' failed: {:#}", destination.url, e);
                    }
                }
            }
            if failed > 0 {
                return Err(anyhow::anyhow!(
                    "{} of {} test webhook(s) failed",
                    failed,
                    destinations.len()
                ));
            }
        }

        Command::Init {
            ref contract_id,
            ref network,
            ref horizon_url,
            ref webhook_url,
            ref label,
            ref rules,
            ref output,
            force,
            non_interactive,
        } => {
            // #228: detect non-TTY stdin or explicit --non-interactive flag
            let interactive = !non_interactive && std::io::stdin().is_terminal();

            // If not interactive, collect all missing required fields upfront and fail.
            if !interactive {
                let mut missing: Vec<&str> = Vec::new();
                if contract_id.is_none() {
                    missing.push("--contract-id");
                }
                if webhook_url.is_none() {
                    missing.push("--webhook-url");
                }
                if !missing.is_empty() {
                    anyhow::bail!(
                        "stdin is not a terminal; the following required flags are missing: {}",
                        missing.join(", ")
                    );
                }
            }

            // #229: Validate --network before prompting for anything else.
            if let Some(n) = network.as_deref() {
                if n != "mainnet" && n != "testnet" && n != "futurenet" && horizon_url.is_none() {
                    anyhow::bail!(
                        "unknown network '{}'; use mainnet, testnet, futurenet, or pass --horizon-url for a custom network",
                        n
                    );
                }
            }

            // #227: check file existence before any prompts
            if output.exists() && !force {
                return Err(anyhow::anyhow!(
                    "'{}' already exists; pass --force to overwrite it",
                    output.display()
                ));
            }

            let contract_id = if interactive {
                value_or_prompt(contract_id, "Contract ID (C...)")?
            } else {
                contract_id.clone().unwrap()
            };

            let network = match network {
                Some(n) => n.clone(),
                None => {
                    if interactive {
                        prompt("Network [testnet]")?
                            .filter(|n| !n.is_empty())
                            .unwrap_or_else(|| "testnet".into())
                    } else {
                        "testnet".into()
                    }
                }
            };

            let webhook_url = if interactive {
                value_or_prompt(webhook_url, "Webhook URL")?
            } else {
                webhook_url.clone().unwrap()
            };

            // #229: label and horizon_url
            let label = match label {
                Some(l) => l.clone(),
                None => {
                    if interactive {
                        prompt("Contract label [My Contract]")?
                            .filter(|l| !l.is_empty())
                            .unwrap_or_else(|| "My Contract".into())
                    } else {
                        "My Contract".into()
                    }
                }
            };

            let raw = render_init_config(
                &contract_id,
                &network,
                horizon_url.as_deref(),
                &webhook_url,
                &label,
                rules,
            )?;

            // Validate with the config crate before touching the filesystem.
            AppConfig::parse(&raw, output).context("the generated config is not valid")?;

            // #471: write the config exactly once. The content goes to a sibling
            // temp file created with `create_new` and mode 0600 (it may hold a
            // webhook secret), which is then renamed over the target. Without
            // `--force` the rename must not clobber a file that appeared after
            // the existence check above (#227), so we re-check and use a
            // no-clobber rename where the platform supports it.
            write_config_file(output, &raw, force)?;
            println!(
                "Wrote {}. Check it with: txwatch --config {} validate",
                output.display(),
                output.display()
            );
        }

        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "txwatch",
                &mut std::io::stdout(),
            );
        }

        Command::Man => {
            match clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout()) {
                // The reader (e.g. `| head`) closing early isn't an error.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                other => other.context("failed to render the man page")?,
            }
        }

        Command::Replay {
            ref contract,
            ref tx,
            send,
            force,
        } => {
            // #222: validate and normalise the transaction hash before use.
            let tx = validate_tx_hash(tx)?;

            let cfg = load_config(&cli)?;
            let contract = find_contract_by_label(&cfg, contract)?;
            let client = build_client().context("failed to build HTTP client")?;

            let payloads = txwatch_poller::replay_transaction(&client, &contract, &tx).await?;
            let payloads =
                txwatch_poller::replay_transaction(&client, &contract, tx, force).await?;
            println!(
                "{} rule(s) matched transaction {} for '{}'",
                payloads.len(),
                tx,
                contract.label
            );
            for payload in &payloads {
                println!();
                println!("  rule: {}", payload.rule_triggered);
                println!("{}", serde_json::to_string_pretty(payload)?);
            }

            if send {
                // #223: use the poller's deliver_alert so that rule-level URL/secret
                // routing and destination filtering match the live watch path exactly.
                let mut failed = 0u64;
                for payload in &payloads {
                    failed += txwatch_poller::deliver_alert(&client, &contract, payload).await;
                }
                if failed > 0 {
                    return Err(anyhow::anyhow!("{} webhook delivery(ies) failed", failed));
                }
            }
        }

        Command::Cursors { action, force } => {
            let cfg = load_config(&cli)?;
            let cursor_file = cfg.cursor_file.as_deref().ok_or_else(|| {
                anyhow::anyhow!("cursor_file is not set in the config; no cursors to manage")
            })?;
            // #442: check by trying to take the same lock `watch` holds, not by
            // whether the lock file exists. The OS releases the lock when its
            // owner dies, so a file left behind by a crash never blocks this.
            // Holding the lock for the edit also stops `watch` starting midway.
            let _state_lock = cursors_state_lock(cfg.state_path(), force)?;
            let cursor_path = std::path::Path::new(cursor_file);
            let mut cursors: std::collections::BTreeMap<String, String> = if cursor_path.exists() {
                let raw = fs::read_to_string(cursor_path)
                    .with_context(|| format!("failed to read cursor file '{}'", cursor_file))?;
                if raw.trim().is_empty() {
                    std::collections::BTreeMap::new()
                } else {
                    serde_json::from_str(&raw)
                        .with_context(|| format!("failed to parse cursor file '{}'", cursor_file))?
                }
            } else {
                std::collections::BTreeMap::new()
            };
            match action {
                CursorsAction::Show => {
                    if cursors.is_empty() {
                        println!("No saved cursors in '{}'.", cursor_file);
                    } else {
                        println!("Saved cursors in '{}':", cursor_file);
                        for contract in &cfg.contracts {
                            let key = txwatch_config::cursor_key(&contract.network, &contract.contract_id);
                            let token = cursors.get(&key).map(String::as_str).unwrap_or("now (default)");
                            println!("  [{network}] {label}", network = contract.network.display_name(), label = contract.label);
                            println!("    key   : {}", key);
                            println!("    cursor: {}", token);
                        }
                        // Also show any stale keys not in config
                        let configured_keys: std::collections::HashSet<String> = cfg.contracts.iter()
                            .map(|c| txwatch_config::cursor_key(&c.network, &c.contract_id))
                            .collect();
                        let stale: Vec<_> = cursors.keys().filter(|k| !configured_keys.contains(*k)).collect();
                        if !stale.is_empty() {
                            println!("  Stale entries (not in current config):");
                            for key in stale {
                                println!("    {} = {}", key, cursors[key]);
                            }
                        }
                    }
                }
                CursorsAction::Set { contract: contract_label, cursor, ledger } => {
                    let contract = cfg.contracts.iter()
                        .find(|c| c.label == contract_label)
                        .ok_or_else(|| anyhow::anyhow!("configured contract '{}' not found", contract_label))?;
                    let key = txwatch_config::cursor_key(&contract.network, &contract.contract_id);
                    let new_cursor = if let Some(cur) = cursor {
                        cur
                    } else if let Some(ledger_seq) = ledger {
                        // Horizon uses paging tokens, but a ledger sequence can be used as a starting point.
                        // We store it with a prefix so the poller knows to resolve it.
                        format!("{}", ledger_seq)
                    } else {
                        return Err(anyhow::anyhow!("--cursor or --ledger is required"));
                    };
                    cursors.insert(key.clone(), new_cursor.clone());
                    let serialized = serde_json::to_string_pretty(&cursors)?;
                    let tmp = cursor_path.with_extension("tmp");
                    fs::write(&tmp, serialized)
                        .with_context(|| format!("failed to write '{}'", tmp.display()))?;
                    fs::rename(&tmp, cursor_path)
                        .with_context(|| format!("failed to replace '{}'", cursor_file))?;
                    println!("Updated cursor for '{}' (key: {}) to: {}", contract_label, key, new_cursor);
                }
                CursorsAction::Reset { contract: contract_label } => {
                    if let Some(label) = contract_label {
                        let contract = cfg.contracts.iter()
                            .find(|c| c.label == label)
                            .ok_or_else(|| anyhow::anyhow!("configured contract '{}' not found", label))?;
                        let key = txwatch_config::cursor_key(&contract.network, &contract.contract_id);
                        cursors.remove(&key);
                        println!("Reset cursor for '{}' to 'now'.", label);
                    } else {
                        let configured_keys: std::collections::HashSet<String> = cfg.contracts.iter()
                            .map(|c| txwatch_config::cursor_key(&c.network, &c.contract_id))
                            .collect();
                        for key in &configured_keys {
                            cursors.remove(key);
                        }
                        println!("Reset all {} contract cursor(s) to 'now'.", configured_keys.len());
                    }
                    let serialized = serde_json::to_string_pretty(&cursors)?;
                    let tmp = cursor_path.with_extension("tmp");
                    fs::write(&tmp, serialized)
                        .with_context(|| format!("failed to write '{}'", tmp.display()))?;
                    fs::rename(&tmp, cursor_path)
                        .with_context(|| format!("failed to replace '{}'", cursor_file))?;
                }
            }
        }

        Command::PruneCursors { dry_run } => {
            let cfg = load_config(&cli)?;
            let Some(cursor_file) = &cfg.cursor_file else {
                anyhow::bail!("no cursor_file configured in txwatch config");
            };
            let removed = prune_cursors(cursor_file, &cfg, dry_run)?;
            if removed.is_empty() {
                println!("No stale cursor entries found in '{}'.", cursor_file);
            } else {
                let verb = if dry_run { "Would remove" } else { "Removed" };
                println!(
                    "{} {} stale cursor entr{} from '{}':",
                    verb,
                    removed.len(),
                    if removed.len() == 1 { "y" } else { "ies" },
                    cursor_file
                );
                for key in &removed {
                    println!("  - {}", key);
                }
            }
        }

        Command::Schema { payload, batch } => {
            if batch {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&schemars::schema_for!(txwatch_rules::AlertBatch))?
                );
            } else if payload {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&schemars::schema_for!(txwatch_rules::AlertPayload))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&schemars::schema_for!(txwatch_config::AppConfig))?
                );
            }
        }

        Command::Watch {
            dry_run,
            once,
            watch_config,
            concurrency,
            #[cfg(feature = "metrics")]
            metrics_addr,
        } => {
            let config_path = required_config(&cli.config)?;
            let cfg = load_config(&cli)?;
            // An explicit --concurrency wins; otherwise use the config value.
            let concurrency = match concurrency {
                Some(n) => n.max(1),
                None => cfg.effective_concurrency(),
            };

            if once {
                info!(
                    version = VERSION,
                    contracts = cfg.contracts.len(),
                    dry_run,
                    concurrency,
                    "running a single TxWatch poll cycle"
                );
                let report =
                    txwatch_poller::run_once_with_concurrency(cfg, dry_run, concurrency).await?;
                info!(
                    transactions = report.transactions,
                    alerts = report.alerts,
                    poll_failures = report.poll_failures,
                    webhook_failures = report.webhook_failures,
                    "poll cycle finished"
                );
                if !report.is_success() {
                    return Err(anyhow::anyhow!(
                        "poll cycle had {} failed contract poll(s) and {} failed webhook delivery(ies)",
                        report.poll_failures,
                        report.webhook_failures
                    ));
                }
                return Ok(());
            }

            // Graceful shutdown: allow the current poll cycle to finish before exiting.
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            spawn_signal_handlers(shutdown_tx);

            #[cfg(feature = "metrics")]
            if let Some(addr) = metrics_addr {
                // Register before serving so the first scrape already has it.
                txwatch_poller::metrics::register_build_info(
                    env!("CARGO_PKG_VERSION"),
                    env!("TXWATCH_GIT_SHA"),
                );
                txwatch_poller::serve_metrics(
                    addr,
                    shutdown_rx.clone(),
                    cfg.readiness_include_webhooks,
                )
                .await?;
            }
            // On Unix this installs a SIGHUP handler; on Windows it is a no-op.
            let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(1);
            spawn_reload_on_sighup(
                config_path.clone(),
                cli.horizon_url.clone(),
                reload_tx.clone(),
            )?;

            let watch_enabled = watch_config || cfg!(windows);
            if watch_enabled {
                spawn_config_watcher(config_path, reload_tx, cli.horizon_url.clone());
            }

            info!(
                version = VERSION,
                contracts = cfg.contracts.len(),
                interval_secs = cfg.poll_interval_seconds,
                dry_run = dry_run,
                concurrency,
                "starting TxWatch"
            );
            txwatch_poller::run_with_reload(cfg, dry_run, shutdown_rx, reload_rx).await?;
        }
    }

    Ok(())
}
/// Write the config file atomically and exactly once (#471):
///  - The content is written to a sibling `<output>.toml.tmp` created with
///    `create_new(true)` and mode 0600 on Unix, so a partial write never leaves
///    a truncated config and the file is never world-readable.
///  - The temp file is then renamed over the target. Without `--force` the
///    target must not exist (TOCTOU fix, #227); with `--force` it is replaced.
fn write_config_file(path: &Path, content: &str, force: bool) -> Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("toml.tmp");
    // Remove a stale temp file from a previous interrupted run; `create_new`
    // below still protects against a concurrent writer.
    let _ = fs::remove_file(&tmp);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("failed to create '{}'", tmp.display()))?;

    // Belt and braces: enforce 0600 even if the umask or platform ignored `mode`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on '{}'", tmp.display()))?;
    }

    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write '{}'", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush '{}'", tmp.display()))?;
    drop(file);

    if !force && path.exists() {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "'{}' already exists; pass --force to overwrite it",
            path.display()
        ));
    }

    fs::rename(&tmp, path).with_context(|| {
        let _ = fs::remove_file(&tmp);
        format!("failed to write '{}'", path.display())
    })?;
    Ok(())
}

/// Read one trimmed line from stdin after printing `label`; `None` on EOF.
fn prompt(label: &str) -> Result<Option<String>> {
    use std::io::{BufRead, Write};
    eprint!("{label}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read from stdin")?;
    Ok((read > 0).then(|| line.trim().to_owned()))
}

fn value_or_prompt(value: &Option<String>, label: &str) -> Result<String> {
    match value {
        Some(v) => Ok(v.clone()),
        None => prompt(label)?
            .filter(|v| !v.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{label} is required")),
    }
}

/// Starter config for `txwatch init`.
///
/// Supported rule presets (via `--rule`):
///   any-transaction        → type = "AnyTransaction"
///   failed                 → type = "TransactionFailed"
///   admin                  → type = "AdminFunctionCalled" with common admin function names
///   large-transfer=<xlm>   → type = "LargeTransfer" with threshold_xlm = <xlm>
///   high-fee=<stroops>     → type = "HighFee" with threshold_stroops = <stroops>
///   function=<name>        → type = "FunctionCalled" with function_name = <name>
fn render_init_config(
    contract_id: &str,
    network: &str,
    horizon_url: Option<&str>,
    webhook_url: &str,
    label: &str,
    rule_presets: &[String],
) -> Result<String> {
    // TOML basic strings share JSON's escaping, so serde_json quotes values safely.
    let quote = |s: &str| serde_json::to_string(s);

    // Build rule TOML snippets from presets; default to AnyTransaction if none given.
    let rule_toml = if rule_presets.is_empty() {
        "  [[contracts.rules]]\n  type = \"AnyTransaction\"\n".to_owned()
    } else {
        let mut parts = String::new();
        for preset in rule_presets {
            let snippet = parse_rule_preset(preset)?;
            parts.push_str(&snippet);
        }
        parts
    };

    // A custom Horizon URL makes the network a custom inline table; otherwise
    // the network is just its name.
    let network_value = match horizon_url {
        Some(url) => format!("{{ horizon_url = {} }}", quote(url)?),
        None => quote(network)?,
    };

    Ok(format!(
        r#"# Generated by `txwatch init`. See docs/configuration.md for every option.
poll_interval_seconds = 10

[[contracts]]
label       = {label}
contract_id = {contract_id}
network     = {network}
webhook_url = {webhook_url}
# webhook_secret = "${{TXWATCH_WEBHOOK_SECRET}}"   # optional: signs each webhook

{rule_toml}"#,
        label = quote(label)?,
        contract_id = quote(contract_id)?,
        network = network_value,
        webhook_url = quote(webhook_url)?,
        rule_toml = rule_toml,
    ))
}

/// Convert a `--rule` preset string into TOML snippet(s).
fn parse_rule_preset(preset: &str) -> Result<String> {
    let quote = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| format!("\"{}\"", s));
    if preset.eq_ignore_ascii_case("any-transaction") {
        Ok("  [[contracts.rules]]\n  type = \"AnyTransaction\"\n".to_owned())
    } else if preset.eq_ignore_ascii_case("failed") {
        Ok("  [[contracts.rules]]\n  type = \"TransactionFailed\"\n".to_owned())
    } else if preset.eq_ignore_ascii_case("admin") {
        Ok(concat!(
            "  [[contracts.rules]]\n",
            "  type           = \"AdminFunctionCalled\"\n",
            "  function_names = [\"set_admin\", \"upgrade\", \"initialize\"]\n",
        )
        .to_owned())
    } else if let Some(rest) = preset.strip_prefix("large-transfer=") {
        let xlm: u64 = rest.parse().with_context(|| {
            format!(
                "invalid large-transfer preset '{}': expected large-transfer=<xlm>",
                preset
            )
        })?;
        Ok(format!(
            "  [[contracts.rules]]\n  type          = \"LargeTransfer\"\n  threshold_xlm = {xlm}\n"
        ))
    } else if let Some(rest) = preset.strip_prefix("high-fee=") {
        let stroops: u64 = rest.parse().with_context(|| {
            format!(
                "invalid high-fee preset '{}': expected high-fee=<stroops>",
                preset
            )
        })?;
        Ok(format!(
            "  [[contracts.rules]]\n  type               = \"HighFee\"\n  threshold_stroops = {stroops}\n"
        ))
    } else if let Some(rest) = preset.strip_prefix("function=") {
        Ok(format!(
            "  [[contracts.rules]]\n  type          = \"FunctionCalled\"\n  function_name = {}\n",
            quote(rest)
        ))
    } else {
        anyhow::bail!(
            "unknown rule preset '{}'; valid presets: any-transaction, failed, admin, \
             large-transfer=<xlm>, high-fee=<stroops>, function=<name>",
            preset
        )
    }
}

/// The config path from `--config`, `TXWATCH_CONFIG` or the `./txwatch.toml`
/// default, which must exist.
fn required_config(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        anyhow::bail!(
            "config file '{}' not found. Pass --config <path>, set TXWATCH_CONFIG, \
             or create ./txwatch.toml (config/example.toml is a starting point)",
            path.display()
        );
    }
    Ok(path.to_path_buf())
}

/// Forward SIGINT, SIGTERM and SIGQUIT into `shutdown_tx` so containers and
/// systemd (`docker stop`, Kubernetes) shut down cleanly. A second SIGINT
/// forces an immediate exit.
#[cfg(unix)]
fn spawn_signal_handlers(shutdown_tx: watch::Sender<bool>) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = ?e, "failed to install SIGINT handler");
            return;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = ?e, "failed to install SIGTERM handler");
            return;
        }
    };
    let mut sigquit = match signal(SignalKind::quit()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = ?e, "failed to install SIGQUIT handler");
            return;
        }
    };

    tokio::spawn(async move {
        let mut shutting_down = false;
        loop {
            let is_sigint = tokio::select! {
                _ = sigint.recv() => true,
                _ = sigterm.recv() => false,
                _ = sigquit.recv() => false,
            };
            if shutting_down {
                if is_sigint {
                    error!(
                        "second SIGINT received — exiting immediately, state may not be flushed"
                    );
                    std::process::exit(130);
                }
                continue;
            }
            shutting_down = true;
            info!("shutting down, press Ctrl-C again to force");
            let _ = shutdown_tx.send(true);
        }
    });
}

#[cfg(not(unix))]
fn spawn_signal_handlers(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = ?e, "failed to install Ctrl+C handler");
            return;
        }
        info!("shutting down, press Ctrl-C again to force");
        let _ = shutdown_tx.send(true);
    });
}

/// On SIGHUP, re-read and validate the config file and hand it to the poller.
/// An invalid file is logged and ignored, so the previous config keeps running.
#[cfg(unix)]
fn spawn_reload_on_sighup(
    path: PathBuf,
    horizon_url: Option<String>,
    reload_tx: tokio::sync::mpsc::Sender<AppConfig>,
) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hangup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            info!(path = %path.display(), "SIGHUP received — reloading config");
            if let Some(cfg) = reload_config(&path, horizon_url.as_deref()) {
                if reload_tx.send(cfg).await.is_err() {
                    break;
                }
            }
        }
    });
    Ok(())
}

/// Windows has no SIGHUP, so config reloading is a no-op there. The poller
/// still runs normally; restart the process to pick up a changed config.
#[cfg(not(unix))]
fn spawn_reload_on_sighup(
    _path: PathBuf,
    _horizon_url: Option<String>,
    _reload_tx: tokio::sync::mpsc::Sender<AppConfig>,
) -> Result<()> {
    info!("SIGHUP config reload is not supported on this platform; restart to reload");
    Ok(())
}

/// Default polling interval for the config watcher when notifications are
/// unavailable or explicitly disabled. Kept well above the old 250 ms so an
/// idle process does not constantly re-read and re-hash the config (#480).
const DEFAULT_CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Resolve the polling interval from `TXWATCH_CONFIG_POLL_INTERVAL_MS`,
/// clamped to at least 2 s so a misconfiguration cannot reintroduce the
/// constant disk activity this watcher is meant to avoid.
fn config_poll_interval() -> Duration {
    std::env::var("TXWATCH_CONFIG_POLL_INTERVAL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .map(|d| d.max(DEFAULT_CONFIG_POLL_INTERVAL))
        .unwrap_or(DEFAULT_CONFIG_POLL_INTERVAL)
}

/// Whether to use filesystem notifications. Set
/// `TXWATCH_CONFIG_WATCH_POLL=1` to force polling (e.g. on network mounts
/// where inotify is unreliable).
fn config_watch_use_polling() -> bool {
    matches!(
        std::env::var("TXWATCH_CONFIG_WATCH_POLL").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// `(mtime, size)` for a file, used to skip re-hashing unchanged files.
fn file_stamp(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    let meta = fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Watches the configuration file and any included files for changes.
///
/// Uses the `notify` crate (inotify/kqueue/ReadDirectoryChangesW) by default so
/// an idle process does no disk work. Polling is an opt-in fallback
/// (`TXWATCH_CONFIG_WATCH_POLL=1`) whose interval is configurable via
/// `TXWATCH_CONFIG_POLL_INTERVAL_MS` (default 2 s). In both modes each file's
/// `(mtime, size)` is cached so unchanged files are never re-read or re-hashed.
fn spawn_config_watcher(
    path: PathBuf,
    reload_tx: tokio::sync::mpsc::Sender<AppConfig>,
    horizon_url: Option<String>,
) {
    tokio::spawn(async move {
        let use_polling = config_watch_use_polling();
        let poll_interval = config_poll_interval();
        let debounce_interval = Duration::from_millis(250);

        // Cache of (mtime, size) per watched file so we only re-hash on change.
        let mut stamps: std::collections::HashMap<PathBuf, Option<(std::time::SystemTime, u64)>> =
            std::collections::HashMap::new();
        let mut last_hash = txwatch_config::compute_config_hash(&path).ok();
        for file in watched_config_files(&path) {
            stamps.insert(file.clone(), file_stamp(&file));
        }

        // Notification channel: `notify` events are forwarded here. In polling
        // mode a timer feeds the same channel so the reload logic is shared.
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<()>(16);

        let _watcher = if use_polling {
            info!(
                path = %path.display(),
                interval_ms = poll_interval.as_millis() as u64,
                "watching config by polling"
            );
            let tx = event_tx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(poll_interval).await;
                    if tx.send(()).await.is_err() {
                        break;
                    }
                }
            });
            None
        } else {
            match start_notify_watcher(&path, event_tx.clone()) {
                Ok(watcher) => {
                    info!(path = %path.display(), "watching config with filesystem notifications");
                    Some(watcher)
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        interval_ms = poll_interval.as_millis() as u64,
                        "filesystem notifications unavailable — falling back to polling"
                    );
                    let tx = event_tx.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(poll_interval).await;
                            if tx.send(()).await.is_err() {
                                break;
                            }
                        }
                    });
                    None
                }
            }
        };

        while event_rx.recv().await.is_some() {
            // Debounce: coalesce bursts of events (editors write several times).
            tokio::time::sleep(debounce_interval).await;
            while event_rx.try_recv().is_ok() {}

            // Skip re-hashing entirely when no watched file's stamp changed.
            let files = watched_config_files(&path);
            let mut changed = false;
            for file in &files {
                let stamp = file_stamp(file);
                if stamps.get(file) != Some(&stamp) {
                    stamps.insert(file.clone(), stamp);
                    changed = true;
                }
            }
            if !changed {
                continue;
            }

            let current_hash = match txwatch_config::compute_config_hash(&path) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if last_hash.as_ref() == Some(&current_hash) {
                continue;
            }
            last_hash = Some(current_hash);
            info!(path = %path.display(), "config file change detected — reloading config");

            if let Some(cfg) = reload_config(&path, horizon_url.as_deref()) {
                if reload_tx.send(cfg).await.is_err() {
                    break;
                }
            }
            // Includes may have changed; refresh the stamp cache.
            for file in watched_config_files(&path) {
                stamps.insert(file.clone(), file_stamp(&file));
            }
        }
    });
}

/// The root config plus every file it includes, resolved from the parsed
/// config. Falls back to just the root file if parsing fails.
fn watched_config_files(path: &Path) -> Vec<PathBuf> {
    let mut files = vec![path.to_path_buf()];
    if let Ok(cfg) = AppConfig::from_file(path) {
        for included in cfg.loaded_files() {
            let included = PathBuf::from(included);
            if !files.contains(&included) {
                files.push(included);
            }
        }
    }
    files
}

/// Install a `notify` watcher on the config's parent directory (so atomic
/// renames and symlink swaps are seen) and forward events to `event_tx`.
fn start_notify_watcher(
    path: &Path,
    event_tx: tokio::sync::mpsc::Sender<()>,
) -> Result<notify::RecommendedWatcher> {
    use notify::{RecursiveMode, Watcher};

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            // Non-blocking send; a full channel already means a reload is pending.
            let _ = event_tx.try_send(());
        }
    })
    .context("failed to create filesystem watcher")?;

    // Watch the directory rather than the file so editors that write-then-rename
    // (and Kubernetes ConfigMap symlink swaps) still produce events.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let watch_root = dir.unwrap_or_else(|| Path::new("."));
    watcher
        .watch(watch_root, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch '{}'", watch_root.display()))?;
    Ok(watcher)
}

/// Re-read and validate the config file.
fn reload_config(path: &Path, horizon_url: Option<&str>) -> Option<AppConfig> {
    match AppConfig::from_file(path) {
        Ok(mut cfg) => {
            warn_empty_include_globs(&cfg);
            if let Some(url) = horizon_url {
                let url = url.trim_end_matches('/');
                for c in &mut cfg.contracts {
                    c.horizon_base_url_override = Some(url.to_string());
                }
            }
            Some(cfg)
        }
        Err(e) => {
            error!(error = %format!("{:#}", e), "config reload failed — keeping the previous config");
            None
        }
    }
}

/// Remove cursor entries whose `<network>:<contract_id>` key matches no
/// configured contract. Returns the removed keys. When `dry_run` is set the
/// file is left untouched.
fn prune_cursors(path: &str, cfg: &AppConfig, dry_run: bool) -> Result<Vec<String>> {
    let path = Path::new(path);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read cursor file '{}'", path.display()))?;
    let mut cursors: std::collections::BTreeMap<String, String> = if raw.trim().is_empty() {
        std::collections::BTreeMap::new()
    } else {
        serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse cursor file '{}'", path.display()))?
    };

    let configured: std::collections::HashSet<String> = cfg
        .contracts
        .iter()
        .map(|c| format!("{}:{}", c.network.as_str(), c.contract_id))
        .collect();

    let stale: Vec<String> = cursors
        .keys()
        .filter(|key| !configured.contains(*key))
        .cloned()
        .collect();

    if !dry_run && !stale.is_empty() {
        for key in &stale {
            cursors.remove(key);
        }
        let serialized = serde_json::to_string_pretty(&cursors)?;
        // Write to a sibling temp file and rename so a crash can't truncate it.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serialized)
            .with_context(|| format!("failed to write '{}'", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("failed to replace '{}'", path.display()))?;
    }

    Ok(stale)
}

/// #410: an include glob that matches nothing loads fine but monitors nothing
/// from that location, so surface it.
fn warn_empty_include_globs(cfg: &AppConfig) {
    for m in cfg.empty_include_globs() {
        warn!(pattern = %m.pattern, "include glob matches no files");
    }
}

/// Load the config and apply `--horizon-url`, if given, to every contract.
fn load_config(cli: &Cli) -> Result<AppConfig> {
    let mut cfg = AppConfig::from_file(&required_config(&cli.config)?)?;
    warn_empty_include_globs(&cfg);
    if let Some(url) = &cli.horizon_url {
        let url = url.trim_end_matches('/');
        for c in &mut cfg.contracts {
            c.horizon_base_url_override = Some(url.to_string());
        }
    }
    Ok(cfg)
}

/// The Horizon base URL actually used to poll `contract`: the per-contract
/// override (including `--horizon-url`) when set, otherwise the network default.
fn poll_base_url(contract: &txwatch_config::WatchedContract) -> &str {
    contract
        .horizon_base_url_override
        .as_deref()
        .unwrap_or_else(|| contract.network.horizon_base_url())
}

/// Find a configured contract by label, matching case-insensitively after
/// trimming (config validation treats such labels as duplicates). On a miss the
/// error lists the configured labels.
fn find_contract_by_label(
    cfg: &AppConfig,
    wanted: &str,
) -> Result<txwatch_config::WatchedContract> {
    let wanted = wanted.trim();
    cfg.contracts
        .iter()
        .find(|c| c.label.trim().eq_ignore_ascii_case(wanted))
        .cloned()
        .ok_or_else(|| {
            let labels: Vec<&str> = cfg.contracts.iter().map(|c| c.label.as_str()).collect();
            if labels.is_empty() {
                anyhow::anyhow!(
                    "configured contract '{}' not found (no contracts are configured)",
                    wanted
                )
            } else {
                anyhow::anyhow!(
                    "configured contract '{}' not found; configured labels: {}",
                    wanted,
                    labels.join(", ")
                )
            }
        })
}

/// Validate a `--horizon-url` / `--explorer-url` value: it must be an absolute
/// http(s) URL. Trailing slashes are trimmed so the stored value is canonical.
fn parse_horizon_url(value: &str) -> Result<String, String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("URL must not be empty".to_string());
    }
    if let Some(err) = txwatch_config::check_http_url(trimmed) {
        return Err(format!("invalid URL '{}': {}", value, err));
    }
    Ok(trimmed.to_string())
}

/// Machine-readable `validate` summary. Webhook secrets are never printed;
/// only whether one is set.
fn config_summary_json(cfg: &AppConfig) -> serde_json::Value {
    let contracts: Vec<_> = cfg
        .contracts
        .iter()
        .map(|c| {
            let rules: Vec<_> = c
                .rules
                .iter()
                .map(|entry| {
                    let mut obj = serde_json::to_value(&entry.rule)
                        .unwrap_or_else(|_| serde_json::json!({}));
                    if let Some(map) = obj.as_object_mut() {
                        // #481: include every rule-level setting so the JSON
                        // output can be used to audit what will actually run.
                        map.insert("enabled".to_string(), serde_json::json!(entry.enabled));
                        map.insert(
                            "severity".to_string(),
                            serde_json::to_value(entry.severity)
                                .unwrap_or(serde_json::Value::Null),
                        );
                        map.insert(
                            "cooldown_seconds".to_string(),
                            serde_json::json!(entry.cooldown_seconds),
                        );
                        map.insert(
                            "cooldown_summary".to_string(),
                            serde_json::json!(entry.cooldown_summary),
                        );
                        map.insert(
                            "webhook_url_set".to_string(),
                            serde_json::json!(entry.webhook_url.is_some()),
                        );
                        map.insert(
                            "webhook_secret_set".to_string(),
                            serde_json::json!(entry.webhook_secret.is_some()),
                        );
                    }
                    obj
                })
                .collect();
            let horizon_url = c
                .horizon_base_url_override
                .as_deref()
                .unwrap_or_else(|| c.network.horizon_base_url());
            serde_json::json!({
                "label": c.label,
                "contract_id": c.contract_id,
                "network": c.network.as_str(),
                "enabled": c.enabled,
                "poll_interval_seconds": c.effective_poll_interval(cfg.poll_interval_seconds),
                "webhook_url": c.webhook_url,
                "webhook_secret_set": c.webhook_secret.is_some(),
                "rules": rules,
                "horizon_url": horizon_url,
                "explorer_url": c.network.explorer_base_url().map(|e| format!("{}/contract/{}", e, c.contract_id)),
                "webhooks": c.destinations().iter().map(destination_summary_json).collect::<Vec<_>>(),
            })
        })
        .collect();
    // #410: each include pattern with the number of files it matched.
    let includes: Vec<_> = cfg
        .include_matches
        .iter()
        .map(|m| {
            serde_json::json!({
                "pattern": m.pattern,
                "glob": m.is_glob,
                "matched_files": m.files.len(),
            })
        })
    // #481: include every effective top-level setting and the loaded files.
    let loaded_files: Vec<String> = cfg
        .loaded_files()
        .into_iter()
        .map(str::to_string)
        .collect();
    serde_json::json!({
        "valid": true,
        "poll_interval_seconds": cfg.poll_interval_seconds,
        "cursor_file": cfg.cursor_file,
        "includes": includes,
        "state_file": cfg.state_file,
        "include": cfg.include,
        "loaded_files": loaded_files,
        "max_contracts": cfg.max_contracts,
        "max_pages_per_cycle": cfg.max_pages_per_cycle,
        "concurrency": cfg.concurrency,
        "readiness_policy": cfg.readiness_policy,
        "contracts": contracts,
    })
}

/// One-line description of a destination for `validate`. Secrets and routing
/// keys are shown only as set/none and header values are redacted.
fn describe_destination(destination: &WebhookDestination) -> String {
    let mut parts = vec![
        format!("format: {}", destination.format),
        format!(
            "secret: {}",
            if destination.secret.is_some() {
                "set"
            } else {
                "none"
            }
        ),
    ];
    if !destination.headers.is_empty() {
        parts.push(format!(
            "headers: {}",
            destination.headers.redacted().join(", ")
        ));
    }
    if destination.routing_key.is_some() {
        parts.push(format!("routing_key: {}", REDACTED));
    }
    if destination.client_cert.is_some() {
        parts.push("mtls: set".to_string());
    }
    if let Some(min) = &destination.min_severity {
        parts.push(format!("min_severity: {}", min));
    }
    if !destination.rule_types.is_empty() {
        parts.push(format!("rule_types: {}", destination.rule_types.join(", ")));
    }
    format!("{} ({})", destination.url, parts.join(", "))
}

/// `validate --format json` entry for a destination, with the same redaction.
fn destination_summary_json(destination: &WebhookDestination) -> serde_json::Value {
    let headers: serde_json::Map<String, serde_json::Value> = destination
        .headers
        .iter()
        .map(|(name, _)| (name.to_owned(), serde_json::Value::from(REDACTED)))
        .collect();
    serde_json::json!({
        "url": destination.url,
        "format": destination.format,
        "secret_set": destination.secret.is_some(),
        "headers": headers,
        "routing_key_set": destination.routing_key.is_some(),
        "mtls_set": destination.client_cert.is_some(),
        "min_severity": destination.min_severity,
        "rule_types": destination.rule_types,
    })
}

/// Every `WebhookFormat` variant name, in declaration order, for help and
/// error messages.
fn webhook_format_names() -> Vec<&'static str> {
    [
        WebhookFormat::Txwatch,
        WebhookFormat::Slack,
        WebhookFormat::Discord,
        WebhookFormat::PagerDuty,
        WebhookFormat::Teams,
        WebhookFormat::Template,
    ]
    .into_iter()
    .map(WebhookFormat::as_str)
    .collect()
}

fn parse_webhook_format(value: &str) -> Result<WebhookFormat, String> {
    serde_json::from_value(serde_json::Value::from(value)).map_err(|_| {
        format!(
            "unknown format '{}': use {}",
            value,
            webhook_format_names().join(", ")
        )
    })
}

/// Validate and normalise a transaction hash for use in Horizon URLs.
///
/// Accepts exactly 64 hexadecimal characters (case-insensitive) with an
/// optional `0x` prefix, which is stripped. Returns an error for anything
/// else so that whitespace, slashes and other junk never reach the URL.
fn validate_tx_hash(raw: &str) -> Result<String> {
    let hash = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if hash.len() != 64 {
        anyhow::bail!(
            "invalid transaction hash {:?}: expected 64 hex characters (got {})",
            raw,
            hash.len()
        );
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "invalid transaction hash {:?}: must contain only hex characters [0-9a-fA-F]",
            raw
        );
    }
    Ok(hash.to_lowercase())
}

/// Parses repeated `--header "Name: value"` arguments.
fn parse_headers(raw: &[String]) -> Result<WebhookHeaders> {
    let mut headers = WebhookHeaders::default();
    let mut seen_lower: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for header in raw {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("--header must look like \"Name: value\""))?;
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        let lower = name.to_ascii_lowercase();
        if let Some(existing) = seen_lower.get(&lower) {
            return Err(anyhow::anyhow!(
                "duplicate header name '{}' (conflicts with '{}' case-insensitively)",
                name,
                existing
            ));
        }
        seen_lower.insert(lower, name.clone());
        headers.0.insert(name, value);
    }
    Ok(headers)
}

/// Outcome of probing one webhook destination. `ok` is the single source of
/// truth for pass/fail in both text and JSON output.
#[derive(serde::Serialize)]
struct WebhookCheck {
    reachable: bool,
    status: Option<u16>,
    ok: bool,
}

impl WebhookCheck {
    /// A 2xx/3xx response, or 401/403 (reachable but auth required), passes.
    fn from_status(status: StatusCode) -> Self {
        let ok = status.is_success()
            || status.is_redirection()
            || status == StatusCode::UNAUTHORIZED
            || status == StatusCode::FORBIDDEN;
        Self {
            reachable: true,
            status: Some(status.as_u16()),
            ok,
        }
    }
}

fn describe_webhook_check(check: &WebhookCheck) -> String {
    match check.status {
        Some(401) | Some(403) => "reachable (auth required)".to_owned(),
        Some(code) if check.ok => format!("reachable (HTTP {})", code),
        Some(code) => format!("HTTP {}", code),
        None => "unreachable".to_owned(),
    }
}

/// Probe one destination using its own configured client (mTLS, custom
/// headers, secrets) so the check reflects what the notifier will actually do.
async fn check_webhook(
    client: &Client,
    destination: &WebhookDestination,
    mode: WebhookCheckMode,
) -> Result<WebhookCheck> {
    let probe = destination_client(client, destination)?;
    if mode == WebhookCheckMode::Post {
        let payload = serde_json::json!({ "test": true });
        let result = send_to_destination_simple(&probe, destination, &payload).await?;
        return Ok(WebhookCheck::from_status(result.final_status));
    }

    let mut request = probe.head(&destination.url);
    for (name, value) in destination.headers.iter() {
        request = request.header(name, value);
    }
    let resp = request.send().await?;
    let status = resp.status();
    if status == StatusCode::METHOD_NOT_ALLOWED || status == StatusCode::NOT_IMPLEMENTED {
        let mut options = probe.request(reqwest::Method::OPTIONS, &destination.url);
        for (name, value) in destination.headers.iter() {
            options = options.header(name, value);
        }
        let options = options.send().await?;
        return Ok(WebhookCheck::from_status(options.status()));
    }
    Ok(WebhookCheck::from_status(status))
}

struct HorizonCheck {
    contract: String,
    contract_id: String,
    network: String,
    status: &'static str,
    latest_ledger: Option<u64>,
    reachable: bool,
    found: bool,
    message: String,
    passphrase_ok: bool,
}

/// Shared pass/fail rule for a Horizon check, used by both the text and JSON
/// `validate` output (#473).
fn check_passed(check: &HorizonCheck) -> bool {
    check.reachable && check.found && check.passphrase_ok
}

async fn check_horizon_contract(
    client: &Client,
    contract: &txwatch_config::WatchedContract,
) -> HorizonCheck {
    let base = poll_base_url(contract);
    let root = client.get(base).send().await;
    let (reachable, latest_ledger, horizon_passphrase) = match root {
        Ok(response) if response.status().is_success() => {
            let json = response
                .json::<serde_json::Value>()
                .await
                .unwrap_or_default();
            let ledger = json.get("core_latest_ledger").and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
            });
            let passphrase = json
                .get("network_passphrase")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            (true, ledger, passphrase)
        }
        _ => (false, None, None),
    };
    if !reachable {
        return HorizonCheck {
            contract: contract.label.clone(),
            contract_id: contract.contract_id.clone(),
            network: contract.network.as_str().into(),
            status: "unreachable",
            latest_ledger,
            reachable: false,
            found: false,
            message: format!("Horizon {} is unreachable", base),
            passphrase_ok: true,
        };
    }

    // #225: verify network_passphrase reported by Horizon matches what we expect.
    let passphrase_ok = match (contract.network.expected_passphrase(), horizon_passphrase.as_deref()) {
        (Some(expected), Some(actual)) => {
            if expected != actual {
                return HorizonCheck {
                    contract: contract.label.clone(),
                    contract_id: contract.contract_id.clone(),
                    network: contract.network.as_str().into(),
                    status: "passphrase mismatch",
                    latest_ledger,
                    reachable: true,
                    found: false,
                    message: format!(
                        "network_passphrase mismatch: expected {:?}, got {:?}",
                        expected, actual
                    ),
                    passphrase_ok: false,
                };
            }
            true
        }
        // No expected passphrase (custom network without passphrase field) — skip the check.
        _ => true,
    };

    // #472: Horizon's `/accounts/{id}` routes reject `C…` contract addresses
    // with HTTP 400, so probe existence through Soroban RPC `getLedgerEntries`
    // using the contract instance ledger key instead.
    let rpc_url = contract
        .network
        .soroban_rpc_url()
        .map(str::to_owned)
        .or_else(|| contract.soroban_rpc_url_override.clone());
    let Some(rpc_url) = rpc_url else {
        return HorizonCheck {
            network: contract.network.as_str().into(),
            status: "unsupported",
            latest_ledger,
            reachable,
            found: false,
            message: format!(
                "no Soroban RPC endpoint is known for {}; cannot verify contract existence",
                contract.network
            ),
            passphrase_ok,
        };
    };

    let ledger_key = contract_instance_ledger_key(&contract.contract_id);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLedgerEntries",
        "params": { "keys": [ledger_key] },
    });
    let response = client.post(&rpc_url).json(&body).send().await;
    let (found, status, message) = match response {
        Ok(resp) if resp.status().is_success() => {
            let json = resp.json::<serde_json::Value>().await.unwrap_or_default();
            if let Some(error) = json.get("error") {
                let detail = error
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown RPC error");
                (
                    false,
                    "unsupported",
                    format!("Soroban RPC {} rejected getLedgerEntries: {}", rpc_url, detail),
                )
            } else {
                let entries = json
                    .get("result")
                    .and_then(|r| r.get("entries"))
                    .and_then(|e| e.as_array());
                let found = entries.map(|e| !e.is_empty()).unwrap_or(false);
                if found {
                    (
                        true,
                        "found",
                        format!("{} exists on {}", contract.label, contract.network),
                    )
                } else {
                    (
                        false,
                        "not found",
                        format!(
                            "{} not found on {}",
                            contract.contract_id, contract.network
                        ),
                    )
                }
            }
        }
        Ok(resp) if resp.status() == StatusCode::BAD_REQUEST => {
            // Horizon (or a proxy) answered instead of Soroban RPC and does not
            // accept contract addresses — distinguish this from "not found".
            let body = resp.text().await.unwrap_or_default();
            (
                false,
                "unsupported",
                format!(
                    "endpoint {} does not support contract addresses (HTTP 400: {})",
                    rpc_url,
                    body.trim()
                ),
            )
        }
        Ok(resp) => (
            false,
            "unsupported",
            format!(
                "Soroban RPC {} returned HTTP {}",
                rpc_url,
                resp.status().as_u16()
            ),
        ),
        Err(err) => (
            false,
            "unsupported",
            format!("Soroban RPC {} is unreachable: {:#}", rpc_url, err),
        ),
    };
    HorizonCheck {
        contract: contract.label.clone(),
        contract_id: contract.contract_id.clone(),
        network: contract.network.as_str().into(),
        status,
        latest_ledger,
        reachable,
        found,
        message,
        passphrase_ok,
    }
}

/// Build the base64 XDR `LedgerKey::ContractData` for a contract's instance
/// entry, as expected by Soroban RPC `getLedgerEntries`.
fn contract_instance_ledger_key(contract_id: &str) -> String {
    use base64::Engine;
    // LedgerKey::ContractData discriminant is 6; the contract instance is the
    // ContractData entry with key `ScVal::LedgerKeyContractInstance` (type 20).
    let mut bytes = Vec::new();
    bytes.push(6u8); // LedgerKey::ContractData
    bytes.push(0u8); // SCAddress::Contract
    bytes.extend_from_slice(&strkey_to_raw(contract_id));
    bytes.push(20u8); // ScVal::LedgerKeyContractInstance
    bytes.push(1u8); // ContractDataDurability::Persistent
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode a `C…` strkey contract address into its 32 raw bytes. Falls back to
/// the raw bytes of the string if it is not a valid strkey.
fn strkey_to_raw(contract_id: &str) -> [u8; 32] {
    use base64::Engine;
    let mut out = [0u8; 32];
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(contract_id) {
        // 1 version byte + 32 payload bytes + 2 CRC bytes.
        if decoded.len() == 35 {
            out.copy_from_slice(&decoded[1..33]);
            return out;
        }
    }
    let bytes = contract_id.as_bytes();
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}
// ── Tracing initialisation ────────────────────────────────────────────────────

fn init_tracing(format: LogFormat) {
    use tracing_subscriber::{fmt, EnvFilter};
    let builder = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false);
    match format {
        LogFormat::Text => builder.init(),
        // One JSON object per line, with the current span and the full span
        // list so fields such as `contract` and `tx` stay structured.
        LogFormat::Json => builder
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .init(),
    }
}

/// Take the state lock for `txwatch cursors` (#442). A lock held by a running
/// instance is an error naming its PID, unless `force` is set, in which case
/// the command warns and proceeds without the lock.
fn cursors_state_lock(
    state_path: Option<&str>,
    force: bool,
) -> anyhow::Result<Option<txwatch_poller::StateLock>> {
    match txwatch_poller::acquire_state_lock(state_path) {
        Ok(lock) => Ok(Some(lock)),
        Err(err) => match err.downcast_ref::<txwatch_poller::StateLockHeld>() {
            Some(held) if force => {
                eprintln!("warning: {held}; continuing because --force was given");
                Ok(None)
            }
            Some(held) => Err(anyhow::anyhow!(
                "{held}. Stop it before editing cursors, or pass --force."
            )),
            None => Err(err),
        },
    }
}

#[cfg(test)]
mod cursors_lock_tests {
    use super::cursors_state_lock;

    fn temp_state(name: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("txwatch_cli_{}_{}.json", name, std::process::id()));
        let _ = std::fs::remove_file(txwatch_poller::state_lock_path(path.to_str().unwrap()));
        path.display().to_string()
    }

    /// #442: a running instance blocks `txwatch cursors`, naming the lock.
    #[test]
    fn held_lock_blocks_cursors_without_force() {
        let state = temp_state("held");
        let _running = txwatch_poller::acquire_state_lock(Some(&state)).unwrap();
        let err = cursors_state_lock(Some(&state), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("holds the state lock"), "{err}");
        assert!(err.contains("--force"), "{err}");
    }

    /// #442: `--force` is the escape hatch.
    #[test]
    fn force_proceeds_while_the_lock_is_held() {
        let state = temp_state("force");
        let _running = txwatch_poller::acquire_state_lock(Some(&state)).unwrap();
        assert!(cursors_state_lock(Some(&state), true).unwrap().is_none());
    }

    /// #442: a lock file left behind by a crash (no live owner) never blocks.
    #[test]
    fn stale_lock_file_does_not_block_cursors() {
        let state = temp_state("stale");
        std::fs::write(txwatch_poller::state_lock_path(&state), "424242\n").unwrap();
        let lock = cursors_state_lock(Some(&state), false).unwrap();
        assert!(lock.is_some_and(|l| l.is_held()));
    }
}
