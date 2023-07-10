mod app_otp;
mod error;
mod hotp;
mod parser;
mod subcommands;

use std::{error::Error, fs::create_dir_all, path::Path};

use crate::parser::Action;
use clap::Parser;
use colored::Colorize;
use error::AppError;
use parser::Cli;
use rkv::{
    backend::{SafeMode, SafeModeEnvironment},
    Rkv, StoreOptions,
};
use subcommands::{
    delete_subcommand, export_subcommand, import_subcommand, new_subcommand, show_subcommand,
};

// TODO: Should refactor hotp module into an otp crate
// otp crate will contain a folder for hotp
// as well as a common module with Otp trait, formatter trait
//

const SERVICE_NAME: &str = "dev.nathancy.otp";

// how long in seconds you have to wait before you can refresh an eotp
const EOTP_REFRESH_DELAY: u64 = 5;

type AppResult<T> = Result<T, AppError>;

fn build_id(name: &String, user: &Option<String>) -> String {
    match user {
        Some(ref username) => format!("{} ({})", name, username),
        None => name.clone(),
    }
}

impl hotp::Metadata {
    fn to_string(&self, selected: bool) -> String {
        let mut acc = String::new();

        if selected {
            acc.push_str(format!("{}", self.name.yellow().bold()).as_str());
        } else {
            acc.push_str(format!("{}", self.name.yellow().bold()).as_str());
        }

        match self.user {
            Some(ref username) => acc.push_str(format!(" ({})\n", username).as_str()),
            None => acc.push_str("\n"),
        }

        self.issuer.as_ref().and_then(|i| {
            acc.push_str(
                format!("Issuer: {}", i)
                    .truecolor(130, 130, 130)
                    .to_string()
                    .as_str(),
            );
            acc.push('\n');
            Some(())
        });

        self.description
            .as_ref()
            .and_then(|i| Some(acc.push_str(format!("Description: {}\n", i).as_str())));

        if acc.len() > 0 {
            acc.pop();
        }

        return acc;
    }
}

fn main() {
    let root = shellexpand::tilde("~/otp");
    let root_path = Path::new(root.as_ref());

    if let Err(_) = create_dir_all(root_path) {
        eprintln!("Could not create directory at {}", root_path.display());
    }

    let mut manager = rkv::Manager::<SafeModeEnvironment>::singleton()
        .write()
        .unwrap();
    let created_arc = manager
        .get_or_create(root_path, Rkv::new::<SafeMode>)
        .unwrap();
    let env = created_arc.read().unwrap();
    let store = env
        .open_single(SERVICE_NAME, StoreOptions::create())
        .unwrap();

    let arguments = Cli::parse();

    let res = match arguments.get_action() {
        Action::New(args) => new_subcommand(args.clone(), &env, &store),
        Action::Show(args) => show_subcommand(args.clone(), &env, &store),
        Action::Delete(args) => delete_subcommand(args.clone(), &env, &store),
        Action::Export => export_subcommand(&env, &store),
        Action::Import => import_subcommand(&env, &store),
    };

    if let Err(e) = res {
        eprintln!("{}: {}", "error".red(), e);
        eprintln!("{:?}", e.source());
    }
}
