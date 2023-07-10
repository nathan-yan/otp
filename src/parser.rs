use std::ffi::OsStr;

use clap::{builder::TypedValueParser, error::ErrorKind, value_parser, Parser, Subcommand};

use crate::hotp::{Length, MAX_HOTP_LENGTH, MIN_HOTP_LENGTH};

#[derive(Clone)]
struct HotpLengthParser {}

impl HotpLengthParser {
    pub fn new() -> Self {
        Self {}
    }

    fn parse(&self, value: &OsStr) -> Result<Length, clap::Error> {
        let value = value.to_str().ok_or(clap::Error::raw(
            ErrorKind::InvalidUtf8,
            "Could not parse length argument to string.",
        ))?;

        let value: u8 = value.parse().map_err(|err| {
            clap::Error::raw(
                ErrorKind::InvalidValue,
                "Length must be a positive integer.",
            )
        })?;

        let length = Length::new(value).ok_or(clap::Error::raw(
            ErrorKind::ValueValidation,
            format!(
                "Length must be between {} and {}.",
                MIN_HOTP_LENGTH, MAX_HOTP_LENGTH
            ),
        ))?;

        Ok(length)
    }
}

impl TypedValueParser for HotpLengthParser {
    type Value = Length;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let mut c = cmd.clone();
        self.parse(value)
            .map_err(|err| err.with_cmd(cmd).format(&mut c))
    }
}

#[derive(Clone, Debug, Parser)]
pub struct NewArgs {
    pub name: String,

    #[arg(
        short,
        long,
        help = "The email/username for the account associated with this OTP."
    )]
    pub user: Option<String>,

    #[arg(short, long, help = "The website/service that issued this OTP.")]
    pub issuer: Option<String>,

    #[arg(short, long, help = "A personal note for this OTP.")]
    pub description: Option<String>,

    #[arg(
            short,
            long,
            value_parser = HotpLengthParser::new(),
            help = "The number of digits in the OTP, must be between 6 and 10"
        )]
    pub length: Option<Length>,

    #[arg(long, value_parser = value_parser!(u64).range(1..), help = "How often (in seconds) this time-based OTP will refresh. This argument is ignored if the OTP is an event based OTP.", default_value = "30")]
    pub interval: u64,

    #[arg(short, long, help = "Flag declaring this OTP as event based.")]
    pub event: bool,
}

#[derive(Clone, Debug, Parser)]
pub struct DeleteArgs {
    #[arg(help = "The name of the one time password to delete.")]
    pub name: String,

    #[arg(
        short,
        long,
        help = "The email/username for the account associated with this OTP."
    )]
    pub user: Option<String>,
}

#[derive(Clone, Debug, Parser)]
pub struct ShowArgs {
    pub name: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    New(NewArgs),
    Show(ShowArgs),
    Delete(DeleteArgs),
    Export,
    Import,
}

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    action: Action,
}

impl Cli {
    pub fn get_action(&self) -> &Action {
        &self.action
    }
}
