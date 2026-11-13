use clap::{Args, Parser, Subcommand};
use kakao_rust::{auth::Scope, device::Catalog, Error, Result, Store};
use serde::Serialize;
use std::{collections::BTreeSet, fs::File, io::BufReader, net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Self-hosted KakaoTalk message collector and authenticated query API."
)]
struct Cli {
    /// Absolute private directory outside Dropbox and this checkout. No implicit default.
    #[arg(long)]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Native(NativeCommand),
    /// Explicitly initialize private SQLite storage; safe to repeat.
    Init,
    #[command(subcommand)]
    Device(DeviceCommand),
    #[command(subcommand)]
    Token(TokenCommand),
    /// Authorize an account and inspect the saved session.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Atomically ingest normalized JSONL. No production database is read.
    Import {
        #[arg(long)]
        file: PathBuf,
    },
    /// Inspect a caller-supplied offline stream checkpoint.
    Cursor {
        #[arg(long)]
        account_id: String,
        #[arg(long)]
        stream_id: String,
    },
    /// Serve authenticated reads on a loopback address only.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
    },
}
#[derive(Subcommand)]
enum NativeCommand {
    /// Continuously collect new messages; Ctrl-C/SIGTERM stops cleanly.
    Run {
        /// Optional bounded observation window; omit for continuous operation.
        #[arg(long, value_parser=clap::value_parser!(u32).range(1..=86400))]
        run_seconds: Option<u32>,
    },
    /// Read all friend identities, then resume using the reconciled friend cursor.
    FriendsSync,
    /// Read backed-up contact labels; newest timestamp by default, no phone writes.
    ContactsSync {
        #[arg(long)]
        snapshot_id: Option<String>,
    },

    /// Select existing conversation restoration using the verified saved session.
    Restore,
    /// Unlock Drawer history with one hidden My password attempt.
    RestoreKey {
        /// Read PIN from a private pipe instead of the terminal; never put it in argv.
        #[arg(long)]
        pin_stdin: bool,
    },
    /// Download/decrypt history pages with atomic resume; does not send completion.
    RestoreDownload {
        #[arg(long, default_value_t=10000, value_parser=clap::value_parser!(u32).range(1..=10000))]
        max_pages: u32,
    },
    /// Continue verified post-download restoration steps.
    RestoreFollowup,
    /// Read local restoration progress without network requests.
    RestoreStatus,
    /// Explicitly confirm skipping drawer restoration (sends completion POST).
    SkipRestore,
    /// Inspect durable native progress, without contacting the network.
    Status,
    /// Run post-authentication initialization and observe events for a bounded duration.
    Bootstrap {
        #[arg(long,default_value_t=180,value_parser=clap::value_parser!(u16).range(1..=1800))]
        observe_seconds: u16,
    },
}
#[derive(Subcommand)]
enum DeviceCommand {
    /// Select and persist a device profile once; account authorization is a separate step.
    Init {
        #[arg(long)]
        catalog: PathBuf,
    },
    Show,
}
#[derive(Subcommand)]
enum TokenCommand {
    /// Print a new 256-bit secret once. Do not redirect output into the repository.
    Issue(IssueArgs),
    /// Show metadata only, never secret material or verifier hashes.
    List,
    Revoke {
        #[arg(long)]
        id: String,
    },
}
#[derive(Subcommand)]
enum AuthCommand {
    /// Account/password login with hidden TTY input; credentials are not saved.
    Login {
        #[arg(long,default_value_t=180,value_parser=clap::value_parser!(u16).range(1..=600))]
        timeout_seconds: u16,
    },
    /// Request one QR challenge and await phone approval; live compatibility is unverified.
    /// Requires an existing selected device; stores token handoff UNENCRYPTED at rest.
    Qr {
        #[arg(long,default_value_t=180,value_parser=clap::value_parser!(u16).range(1..=600))]
        timeout_seconds: u16,
    },
    /// Inspect local metadata only; never contacts Kakao or prints tokens/QR identifiers.
    Status,
    /// Verify saved credentials and identity locally; displays no account IDs or tokens.
    Session,
}
#[derive(Args)]
#[group(skip)]
#[command(group(clap::ArgGroup::new("room_access").required(true).multiple(false).args(["all_rooms","rooms"])))]
#[command(group(clap::ArgGroup::new("account_source").required(true).multiple(false).args(["account_id","session_account"])))]
struct IssueArgs {
    #[arg(long)]
    label: String,
    #[arg(long)]
    account_id: Option<String>,
    /// Bind to the verified saved Kakao user ID without copying auth credentials.
    #[arg(long)]
    session_account: bool,
    #[arg(long = "scope", value_delimiter = ',', required = true)]
    scopes: Vec<Scope>,
    /// Explicitly permit every room in this account (required for friends:read).
    #[arg(long)]
    all_rooms: bool,
    /// Restrict the credential to these exact room IDs.
    #[arg(long = "room", value_delimiter = ',')]
    rooms: Vec<String>,
    #[arg(long,default_value_t=86400,value_parser=clap::value_parser!(u32).range(1..=31536000))]
    expires_in: u32,
}
fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute(Cli::parse()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn execute(cli: Cli) -> Result<()> {
    if matches!(cli.command, Command::Init) {
        Store::initialize(&cli.data_dir)?;
        return print_json(
            &serde_json::json!({"initialized":true,"source":"offline_import","native_auth":"device_approval","native_sync":false}),
        );
    }
    let store = Store::open(&cli.data_dir)?;
    match cli.command {
        Command::Native(NativeCommand::Run { run_seconds }) => {
            kakao_rust::live::run(&store, async move {
                #[cfg(unix)]
                let mut term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
                tokio::select! {
                    _=tokio::signal::ctrl_c()=>(),
                    _=async { #[cfg(unix)] { term.recv().await; } #[cfg(not(unix))] {std::future::pending::<()>().await;} }=>(),
                    _=async {if let Some(seconds)=run_seconds {tokio::time::sleep(std::time::Duration::from_secs(seconds.into())).await;} else {std::future::pending::<()>().await;}}=>(),
                }
            }).await?;
            print_json(&store.live_status(&store.session_load()?.user_id().to_string())?)
        }
        Command::Native(NativeCommand::ContactsSync { snapshot_id }) => {
            print_json(&kakao_rust::contacts::sync_once(&store, snapshot_id.as_deref()).await?)
        }
        Command::Native(NativeCommand::FriendsSync) => {
            print_json(&kakao_rust::friends::sync_once(&store).await?)
        }
        Command::Native(NativeCommand::Restore) => {
            print_json(&kakao_rust::drawer_restore::begin(&store).await?)
        }
        Command::Native(NativeCommand::RestoreKey { pin_stdin }) => {
            let status = kakao_rust::drawer::unlock::unlock(&store, || {
                if pin_stdin {
                    use std::io::Read;
                    let mut bytes = zeroize::Zeroizing::new(Vec::new());
                    std::io::stdin().take(17).read_to_end(&mut bytes)?;
                    if bytes.len() > 16 {
                        return Err(Error::Invalid("PIN input too long".into()));
                    }
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| Error::Invalid("invalid PIN input".into()))?;
                    Ok(zeroize::Zeroizing::new(
                        text.trim_end_matches(['\r', '\n']).to_owned(),
                    ))
                } else {
                    Ok(zeroize::Zeroizing::new(rpassword::prompt_password(
                        "카카오 지갑 My 비밀번호 (6자리): ",
                    )?))
                }
            })
            .await?;
            print_json(&status)
        }
        Command::Native(NativeCommand::RestoreDownload { max_pages }) => {
            print_json(&kakao_rust::drawer::history::download(&store, max_pages).await?)
        }
        Command::Native(NativeCommand::RestoreFollowup) => {
            print_json(&kakao_rust::drawer::followup::run(&store).await?)
        }
        Command::Native(NativeCommand::RestoreStatus) => {
            print_json(&store.drawer_restore_status()?)
        }
        Command::Native(NativeCommand::SkipRestore) => {
            kakao_rust::native::skip_drawer_restore(&store).await?;
            print_json(&store.runtime_status()?)
        }
        Command::Native(NativeCommand::Status) => print_json(&store.runtime_status()?),
        Command::Native(NativeCommand::Bootstrap { observe_seconds }) => {
            kakao_rust::native::bootstrap_observe(&store, observe_seconds, |notice| {
                if let Ok(value) = serde_json::to_string(&notice) {
                    eprintln!("{value}");
                }
            })
            .await?;
            print_json(&store.runtime_status()?)
        }
        Command::Init => unreachable!(),
        Command::Device(DeviceCommand::Init { catalog }) => {
            // An existing identity is authoritative even if the old catalog file disappears.
            match store.device_show() {
                Ok(profile) => print_json(&profile),
                Err(Error::NotFound) => {
                    let file = File::open(catalog)?;
                    if file.metadata()?.len() > 1024 * 1024 {
                        return Err(Error::Invalid("catalog exceeds 1 MiB".into()));
                    }
                    let catalog: Catalog = serde_json::from_reader(BufReader::new(file))?;
                    print_json(&store.device_initialize(&catalog, chrono::Utc::now().date_naive())?)
                }
                Err(error) => Err(error),
            }
        }
        Command::Device(DeviceCommand::Show) => print_json(&store.device_show()?),
        Command::Token(TokenCommand::Issue(args)) => {
            let account_id = if args.session_account {
                store.session_load()?.user_id().to_string()
            } else {
                args.account_id
                    .ok_or_else(|| Error::Invalid("account source required".into()))?
            };
            let now = chrono::Utc::now().timestamp();
            let rooms = if args.all_rooms {
                None
            } else {
                Some(args.rooms.into_iter().collect::<BTreeSet<_>>())
            };
            print_json(&store.token_issue(
                args.label,
                account_id,
                args.scopes.into_iter().collect(),
                rooms,
                now + i64::from(args.expires_in),
                now,
            )?)
        }
        Command::Auth(AuthCommand::Status) => print_json(&store.auth_status()?),
        Command::Auth(AuthCommand::Session) => print_json(&store.session_load()?.status()),
        Command::Auth(AuthCommand::Login { timeout_seconds }) => {
            store.device_show()?;
            let status = store.auth_status()?;
            if status.recovery_required || status.handoff_present {
                return Err(Error::Conflict(
                    "authorization state requires recovery or is already authorized".into(),
                ));
            }
            let credentials = kakao_rust::password::Credentials::prompt()?;
            let result = kakao_rust::password_auth::authorize_password(
                &store,
                credentials,
                timeout_seconds,
                |notice| match notice {
                    kakao_rust::password_auth::Notice::Passcode {
                        value,
                        remaining_seconds,
                    } => eprintln!(
                        "phone_approval_passcode={value} remaining_seconds={remaining_seconds}"
                    ),
                },
            )
            .await?;
            print_json(&result)
        }
        Command::Auth(AuthCommand::Qr { timeout_seconds }) => {
            eprintln!("QR authorization: tokens are stored in private files.");
            let status = kakao_rust::qr_auth::authorize_qr(
                &store,
                timeout_seconds,
                async {
                    let _ = tokio::signal::ctrl_c().await;
                },
                |notice| match notice {
                    kakao_rust::qr_auth::Notice::QrReady {
                        path,
                        expires_in_seconds,
                    } => eprintln!(
                        "qr_svg={} expires_in_seconds={expires_in_seconds}",
                        path.display()
                    ),
                    kakao_rust::qr_auth::Notice::Passcode {
                        value,
                        remaining_seconds,
                    } => eprintln!(
                        "phone_approval_passcode={value} remaining_seconds={remaining_seconds}"
                    ),
                },
            )
            .await?;
            print_json(&status)
        }
        Command::Token(TokenCommand::List) => print_json(&store.token_list()?),
        Command::Token(TokenCommand::Revoke { id }) => {
            store.token_revoke(&id, chrono::Utc::now().timestamp())?;
            print_json(&serde_json::json!({"revoked":id}))
        }
        Command::Import { file } => {
            if file.as_os_str() == "-" {
                print_json(&store.import_jsonl(std::io::stdin().lock())?)
            } else {
                print_json(&store.import_jsonl(BufReader::new(File::open(file)?))?)
            }
        }
        Command::Cursor {
            account_id,
            stream_id,
        } => print_json(&store.sync_cursor(&account_id, &stream_id)?),
        Command::Serve { bind } => {
            if !bind.ip().is_loopback() {
                return Err(Error::Invalid("only loopback binding is supported".into()));
            }
            let listener = tokio::net::TcpListener::bind(bind).await?;
            eprintln!(
                "listening http://{}; API bearer authentication required",
                listener.local_addr()?
            );
            axum::serve(listener, kakao_rust::api::router(store))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            Ok(())
        }
    }
}
