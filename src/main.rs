use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use yett::error::Error;
use yett::r#ref::Ref;
use yett::resolver::Resolver;

use yett::check::{ACCESS_PATH, SOPS_CONFIG_PATH};

#[derive(Parser)]
#[command(
    name = "yett",
    version,
    about = "Deliver secrets from committed SOPS files"
)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    identity: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long, value_name = "PATH", default_value = ".env.refs")]
        env_file: PathBuf,
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    #[command(
        after_help = "Examples:\n  yett get dev/db/url\n  yett get prod/stripe/api_key\n  yett get 'ref+sops://.yett/secrets.dev.enc.yaml#/db/url'"
    )]
    Get {
        #[arg(value_name = "TIER/POINTER")]
        argument: String,
    },
    Set {
        #[arg(long, value_name = "PATH", default_value = ".env.refs")]
        env_file: PathBuf,
        #[arg(long, value_name = "NAME")]
        r#ref: Option<String>,
        tier: String,
        #[arg(value_name = "POINTER")]
        pointer: String,
    },
    Import {
        #[arg(long, value_name = "PATH", default_value = ".env.local")]
        from: PathBuf,
        #[arg(long, value_name = "T", default_value = "dev")]
        tier: String,
        #[arg(long, value_name = "PATH", default_value = ".env.refs")]
        env_file: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, value_name = "K1,K2")]
        exclude: Option<String>,
        #[arg(long)]
        force: bool,
    },
    Edit {
        tier: String,
    },
    Init {
        #[arg(long, value_name = "TIERS", default_value = "dev")]
        tiers: String,
        #[arg(long, value_name = "HANDLE")]
        handle: Option<String>,
    },
    Keygen {
        #[arg(long, value_name = "TIER", default_value = "dev")]
        tier: String,
        #[arg(long, value_name = "HANDLE")]
        register: Option<String>,
    },
    Check {
        #[arg(long, value_name = "PATH", default_value = ".env.refs")]
        env_file: PathBuf,
    },
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
}

#[derive(Subcommand)]
enum AccessCommand {
    List,
    Add {
        handle: String,
        tier: String,
        #[arg(value_name = "PUBLIC-KEY")]
        public_key: String,
    },
    Remove {
        handle: String,
        #[arg(long)]
        force_prod: bool,
    },
    Sync,
}

fn main() {
    if let Err(error) = yett::harden::harden_process() {
        eprintln!("yett: {error}");
        std::process::exit(error.exit_code());
    }

    let Cli { identity, command } = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let usage = e.use_stderr();
            let _ = e.print();
            std::process::exit(i32::from(usage));
        }
    };
    if let Err(e) = run(identity, command) {
        eprintln!("yett: {e}");
        std::process::exit(e.exit_code());
    }
}

fn run(identity: Option<PathBuf>, command: Command) -> Result<(), Error> {
    match command {
        Command::Run { env_file, command } => yett::run::run(&env_file, identity, &command),
        Command::Get { argument } => get(identity, &argument),
        Command::Set {
            env_file,
            r#ref,
            tier,
            pointer,
        } => yett::edit::set_with_ref(&tier, &pointer, identity, &env_file, r#ref.as_deref()),
        Command::Import {
            from,
            tier,
            env_file,
            dry_run,
            exclude,
            force,
        } => yett::import::import(&from, &tier, &env_file, dry_run, exclude.as_deref(), force),
        Command::Edit { tier } => yett::edit::edit(&tier, identity),
        Command::Init { tiers, handle } => init(&tiers, handle.as_deref()),
        Command::Keygen { tier, register } => keygen(&tier, register.as_deref()),
        Command::Check { env_file } => yett::check::check(&env_file, identity),
        Command::Access { command } => access(identity, command),
    }
}

fn access(identity: Option<PathBuf>, command: AccessCommand) -> Result<(), Error> {
    let path = std::path::Path::new(ACCESS_PATH);
    let mut access = yett::access::AccessList::load(path).map_err(access_error)?;
    match command {
        AccessCommand::List => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| Error::Usage(format!("cannot read {ACCESS_PATH}: {error}")))?;
            print!("{text}");
        }
        AccessCommand::Add {
            handle,
            tier,
            public_key,
        } => {
            access
                .add(&handle, &tier, &public_key)
                .map_err(access_error)?;
            commit_outputs(&access)?;
            println!("added {handle} to {tier}; run `yett access sync` to rewrap encrypted files");
        }
        AccessCommand::Remove { handle, force_prod } => {
            let removed_tiers = access.remove(&handle).map_err(access_error)?;
            let had_prod = removed_tiers.iter().any(|tier| tier == "prod");
            if had_prod && !force_prod {
                return Err(Error::Usage(format!(
                    "{}; rerun with --force-prod to confirm",
                    prod_warning(&handle)
                )));
            }
            yett::access::check_tiers_keep_recipients(
                &access,
                std::path::Path::new(".yett"),
                &removed_tiers,
            )?;
            access.save(path).map_err(access_error)?;
            if had_prod {
                println!("{}", prod_warning(&handle));
            }
            if let Err(error) = write_sops_config(&access).and_then(|()| {
                yett::access::sync(&access, std::path::Path::new(".yett"), identity.as_deref())
            }) {
                eprintln!(
                    "yett: the access list is updated; run `yett access sync` with a remaining identity to finish"
                );
                return Err(error);
            }
        }
        AccessCommand::Sync => {
            write_sops_config(&access)?;
            yett::access::sync(&access, std::path::Path::new(".yett"), identity.as_deref())?;
        }
    }
    Ok(())
}

fn access_error(error: yett::access::AccessError) -> Error {
    Error::Usage(error.to_string())
}

fn write_sops_config(access: &yett::access::AccessList) -> Result<(), Error> {
    yett::onboard::write_sops_config(access, Path::new("."))
}

fn commit_outputs(access: &yett::access::AccessList) -> Result<(), Error> {
    let list_temp = yett::access::stage(
        std::path::Path::new(ACCESS_PATH),
        &access.to_text().map_err(access_error)?,
    )?;
    let config_temp = match yett::access::stage(
        std::path::Path::new(SOPS_CONFIG_PATH),
        &access.render_sops_config(),
    ) {
        Ok(temporary) => temporary,
        Err(error) => {
            let _ = std::fs::remove_file(&list_temp);
            return Err(error);
        }
    };
    if let Err(error) = yett::access::commit(&list_temp, std::path::Path::new(ACCESS_PATH)) {
        let _ = std::fs::remove_file(&list_temp);
        let _ = std::fs::remove_file(&config_temp);
        return Err(error);
    }
    if let Err(error) = yett::access::commit(&config_temp, std::path::Path::new(SOPS_CONFIG_PATH)) {
        let _ = std::fs::remove_file(&config_temp);
        eprintln!("yett: the access list is updated; run `yett access sync` to finish");
        return Err(error);
    }
    Ok(())
}

fn prod_warning(handle: &str) -> String {
    format!(
        "removing {handle} is forward-only: the removed person keeps access to everything already committed and will have no access to future changes; prod values must now be rotated at their source"
    )
}

fn get(identity: Option<PathBuf>, argument: &str) -> Result<(), Error> {
    let r = match argument.starts_with("ref+") {
        true => Ref::parse(argument)?,
        false => {
            let (tier, rest) = argument.split_once('/').ok_or_else(|| {
                Error::Usage(format!(
                    "expected `<tier>/<pointer>`, for example `{argument}/db/url`"
                ))
            })?;
            if rest.is_empty() {
                return Err(Error::Usage(format!(
                    "the pointer for tier `{tier}` is empty; for example `{tier}/db/url`"
                )));
            }
            yett::edit::pointer_reference(tier, &format!("/{rest}"))?
        }
    };
    let secret = Resolver::with_identity(identity).resolve(&r)?;

    let mut out = std::io::stdout().lock();
    out.write_all(secret.expose_secret().as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(|e| Error::Usage(format!("cannot write to stdout: {e}")))
}

fn init(tiers: &str, handle: Option<&str>) -> Result<(), Error> {
    let Some(handle) = handle else {
        let tiers = yett::onboard::parse_tiers(tiers)?;
        let out = yett::onboard::init(Path::new("."), &tiers)?;
        println!("created {}", out.access_path.display());
        println!("created {}", out.sops_path.display());
        println!("created {}", out.env_refs_path.display());
        println!("tiers: {}", out.tiers.join(", "));
        println!("next steps:");
        println!(
            "  1. run `yett keygen --tier <tier>` once per tier ({})",
            out.tiers.join(", ")
        );
        println!(
            "  2. add the printed line under your handle in {}",
            out.access_path.display()
        );
        println!("  3. run `yett access sync`");
        return Ok(());
    };
    let mut prompt = yett::identity::TtyPrompt;
    let out = yett::onboard::init_with_handle(Path::new("."), tiers, handle, &mut prompt, None)?;
    println!("created {}", out.init.access_path.display());
    println!("created {}", out.init.sops_path.display());
    println!("created {}", out.init.env_refs_path.display());
    println!("registered {handle} for {}", out.register.tier);
    println!("public key: {}", out.register.public_key);
    println!(
        "if encrypted files for {} already exist, a current recipient must run `yett access sync`",
        out.register.tier
    );
    Ok(())
}

fn keygen(tier: &str, register: Option<&str>) -> Result<(), Error> {
    let mut prompt = yett::identity::TtyPrompt;
    let Some(handle) = register else {
        let out = yett::onboard::keygen(tier, &mut prompt, None)?;
        println!("wrote {}", out.path.display());
        println!("public key: {}", out.public_key);
        println!(
            "add this line under your handle in {}:",
            yett::onboard::ACCESS_PATH
        );
        println!("{}", out.yaml_line);
        return Ok(());
    };
    let out = yett::onboard::keygen_register(tier, handle, Path::new("."), &mut prompt, None)?;
    if out.reused {
        println!("reused the existing {}", out.path.display());
    } else {
        println!("wrote {}", out.path.display());
    }
    println!("public key: {}", out.public_key);
    println!("registered {handle} for {}", out.tier);
    println!(
        "if encrypted files for {} already exist, a current recipient must run `yett access sync`",
        out.tier
    );
    Ok(())
}
