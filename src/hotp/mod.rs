mod error;
mod util;

use std::{
    num::NonZeroU64,
    time::{SystemTime, UNIX_EPOCH},
};

use secrets::SecretVec;
// use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub use self::error::HotpError;
use self::util::get_hotp;

pub const MIN_HOTP_LENGTH: u8 = 6;
pub const MAX_HOTP_LENGTH: u8 = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Length {
    length: u8,
}

impl Default for Length {
    fn default() -> Self {
        Self {
            length: MIN_HOTP_LENGTH,
        }
    }
}

impl Length {
    pub fn new(length: u8) -> Option<Self> {
        if length > MAX_HOTP_LENGTH || length < MIN_HOTP_LENGTH {
            None
        } else {
            Some(Self { length })
        }
    }

    pub fn get(&self) -> u8 {
        self.length
    }
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub user: Option<String>,
    pub issuer: Option<String>,
    pub description: Option<String>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            user: None,
            issuer: None,
            description: None,
        }
    }
}

impl ToString for Metadata {
    fn to_string(&self) -> String {
        let mut acc = String::new();
        self.user
            .as_ref()
            .and_then(|ref i| Some(acc.push_str(format!("User: {}\n", i).as_str())));

        self.issuer
            .as_ref()
            .and_then(|i| Some(acc.push_str(format!("Issuer: {}\n", i).as_str())));

        self.description
            .as_ref()
            .and_then(|i| Some(acc.push_str(format!("Description: {}\n", i).as_str())));

        return acc;
    }
}

pub struct Secret(SecretVec<u8>);

impl Secret {
    pub fn new(secret: SecretVec<u8>) -> Self {
        Self(secret)
    }

    pub fn get(&self) -> &SecretVec<u8> {
        &self.0
    }

    pub fn try_from_b32(mut b32: String) -> Option<Self> {
        b32.retain(|c| !c.is_whitespace());
        let ret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &b32)
            .and_then(move |mut s| Some(Self(SecretVec::<u8>::from(s.as_mut_slice()))));

        b32.zeroize();

        ret
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self(SecretVec::random(0))
    }
}

// TODO: Get rid of the Hotp struct, just have Totp have a length and a secret

#[derive(Serialize, Deserialize)]
pub struct Hotp {
    pub metadata: Metadata,
    pub length: Length,

    #[serde(skip)]
    secret: Secret,
}

impl Hotp {
    pub fn new(metadata: Metadata, length: Length, secret: Secret) -> Self {
        Self {
            metadata,
            length,
            secret,
        }
    }

    pub fn get_from_counter(&self, counter: u64) -> u32 {
        get_hotp(
            self.secret.0.borrow().get(..).unwrap(),
            counter,
            &self.length,
        )
    }

    pub fn get_secret(&self) -> &Secret {
        &self.secret
    }

    pub fn set_secret(&mut self, secret: Secret) {
        self.secret = secret;
    }
}

pub trait Otp {
    fn get_otp(&self) -> u32;
    fn get_otp_string(&self) -> String;
    fn get_metadata(&self) -> &Metadata;
}

#[derive(Serialize, Deserialize)]
pub struct Eotp {
    pub hotp: Hotp,
    counter: u64,
}

impl Eotp {
    pub fn new(hotp: Hotp, counter: u64) -> Self {
        Self { hotp, counter }
    }

    pub fn increment_counter(&mut self) {
        self.counter += 1;
    }
}

impl Otp for Eotp {
    fn get_otp(&self) -> u32 {
        self.hotp.get_from_counter(self.counter)
    }

    fn get_otp_string(&self) -> String {
        format!(
            "{:0width$}",
            self.get_otp(),
            width = self.hotp.length.get() as usize
        )
    }

    fn get_metadata(&self) -> &Metadata {
        &self.hotp.metadata
    }
}

#[derive(Serialize, Deserialize)]
pub struct Totp {
    pub hotp: Hotp,
    interval: NonZeroU64,
}

impl Totp {
    pub fn new(hotp: Hotp, interval: NonZeroU64) -> Self {
        Self { hotp, interval }
    }

    pub fn remaining_time(&self) -> u64 {
        self.interval.get()
            - (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                % self.interval)
    }
}

impl Otp for Totp {
    fn get_otp(&self) -> u32 {
        let counter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / self.interval;
        self.hotp.get_from_counter(counter)
    }

    fn get_otp_string(&self) -> String {
        format!(
            "{:0width$}",
            self.get_otp(),
            width = self.hotp.length.get() as usize
        )
    }

    fn get_metadata(&self) -> &Metadata {
        &self.hotp.metadata
    }
}
