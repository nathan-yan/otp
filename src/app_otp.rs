use std::time::{Duration, Instant};

use colored::Colorize;
use rkv::{
    backend::{SafeModeDatabase, SafeModeRwTransaction},
    SingleStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, from_value, to_string, to_value, Value};
use zeroize::Zeroize;

use crate::{
    build_id,
    error::AppError,
    hotp::{self, Eotp, Otp, Secret, Totp},
    subcommands::delete_from_id,
    AppResult, EOTP_REFRESH_DELAY, SERVICE_NAME,
};

pub fn default_true() -> bool {
    true
}

pub fn default_ts() -> Instant {
    Instant::now() - Duration::from_secs(EOTP_REFRESH_DELAY)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AppOtp {
    Eotp {
        #[serde(flatten)]
        eotp: Eotp,

        #[serde(skip, default = "default_true")]
        hidden: bool,

        #[serde(skip, default = "default_ts")]
        last_incremented: Instant,
    },
    Totp(Totp),
}

impl TryFrom<&str> for AppOtp {
    type Error = AppError;

    fn try_from(json_str: &str) -> Result<Self, Self::Error> {
        let json = from_str::<Value>(json_str)?;

        // check if the json contains a "secret" field
        let mut secret = None;
        if let Some(secret_value) = json.as_object().unwrap().get("secret") {
            let secret_string = secret_value.as_str().unwrap().to_string();
            secret = Some(
                Secret::try_from_b32(secret_string).ok_or(AppError::GenericError(
                    "Secret must be a valid base32 string.".to_string(),
                ))?,
            );
        }

        let mut app_otp = from_value::<AppOtp>(json)?;

        // if we found a secret field in the json, assign it to the appotp,
        // otherwise try to fill the secret from the keyring
        if let Some(secret) = secret {
            app_otp.set_secret(secret);
        } else {
            let keyring_entry = keyring::Entry::new(SERVICE_NAME, &app_otp.get_id())?;
            if let Ok(b32_secret) = keyring_entry.get_password() {
                if let Some(secret) = hotp::Secret::try_from_b32(b32_secret) {
                    app_otp.set_secret(secret)
                }
            }
        }

        return Ok(app_otp);
    }
}

impl TryFrom<&rkv::Value<'_>> for AppOtp {
    type Error = AppError;

    fn try_from(json: &rkv::Value) -> Result<Self, Self::Error> {
        if let rkv::Value::Json(json) = json {
            return Self::try_from(*json);
        }

        return Err(AppError::GenericError(
            "Tried reading json blob from key value store, but found something else.".to_string(),
        ));
    }
}

impl AppOtp {
    pub fn to_string(&self, selected: bool, show_code: bool) -> String {
        if show_code {
            return format!(
                "{}\n{}",
                self.get_metadata().to_string(selected),
                self.format_otp_string()
            );
        }
        return format!("{}", self.get_metadata().to_string(selected),);
    }

    pub fn get_otp_string(&self) -> String {
        match self {
            Self::Eotp { eotp, hidden, .. } => {
                if *hidden {
                    "-".repeat(eotp.hotp.length.get() as usize)
                } else {
                    eotp.get_otp_string()
                }
            }
            Self::Totp(totp) => totp.get_otp_string(),
        }
    }
    pub fn format_otp_string(&self) -> String {
        let mut otp_string;
        match self {
            Self::Eotp {
                last_incremented, ..
            } => {
                otp_string = self.get_otp_string();
                otp_string.insert((otp_string.len()) / 2, ' ');

                let refresh_refractory_time = EOTP_REFRESH_DELAY
                    .checked_sub(last_incremented.elapsed().as_secs())
                    .unwrap_or(0);

                if refresh_refractory_time == 0 {
                    return otp_string.green().to_string();
                } else {
                    let refresh_refractory_time = format!(" × {}", refresh_refractory_time);
                    return format!("{}{}", otp_string.green(), refresh_refractory_time);
                }
            }
            Self::Totp(totp) => {
                otp_string = totp.get_otp_string();
                otp_string.insert((otp_string.len()) / 2, ' ');

                let remaining_time = format!(" · {}", totp.remaining_time()).bright_white();

                format!("{}{}", otp_string.green(), remaining_time)
            }
        }
    }
    pub fn get_metadata(&self) -> &hotp::Metadata {
        match self {
            Self::Eotp { eotp, .. } => &eotp.hotp.metadata,
            Self::Totp(totp) => &totp.hotp.metadata,
        }
    }

    /**
     * Export the AppOtp along with its secret in json format
     */
    pub fn export(&self) -> AppResult<Value> {
        let id = self.get_id();
        let keyring_entry = keyring::Entry::new(SERVICE_NAME, &id)?;
        let secret = keyring_entry.get_password()?;

        let mut self_json = to_value(&self)?;
        self_json
            .as_object_mut()
            .unwrap()
            .insert("secret".to_string(), Value::String(secret));

        Ok(self_json)
    }

    pub fn import(
        str: &str,
        writer: &mut rkv::Writer<SafeModeRwTransaction>,
        store: &SingleStore<SafeModeDatabase>,
    ) -> AppResult<()> {
        let app_otp = AppOtp::try_from(str)?;
        app_otp.write(writer, store, true)?;

        Ok(())
    }

    pub fn get_secret(&self) -> Option<&hotp::Secret> {
        match self {
            Self::Eotp { eotp, .. } => Some(&eotp.hotp.get_secret()),
            Self::Totp(totp) => Some(&totp.hotp.get_secret()),
        }
    }

    pub fn set_secret(&mut self, secret: hotp::Secret) {
        match self {
            Self::Eotp { eotp, .. } => eotp.hotp.set_secret(secret),
            Self::Totp(totp) => totp.hotp.set_secret(secret),
        }
    }

    pub fn get_id(&self) -> String {
        let metadata = self.get_metadata();

        build_id(&metadata.name, &metadata.user)
    }

    pub fn write(
        &self,
        mut writer: &mut rkv::Writer<SafeModeRwTransaction>,
        store: &SingleStore<SafeModeDatabase>,
        write_secret: bool,
    ) -> AppResult<()> {
        let serialized = to_string(self)?;

        let id = self.get_id();
        store.put(&mut writer, &id, &rkv::Value::Json(serialized.as_str()))?;

        if write_secret {
            if let Some(secret) = self.get_secret() {
                let keyring_entry = keyring::Entry::new(SERVICE_NAME, id.as_str())?;

                // encode and decode allocate vectors with the correct capacity already, so they are
                // not moved on pushes
                // the returned string also uses the same vec as backing, so we just need to zeroize
                // the vec that's wrapped inside the string.
                let mut b32_key = base32::encode(
                    base32::Alphabet::RFC4648 { padding: false },
                    secret.get().borrow().get(..).unwrap(),
                );
                keyring_entry.set_password(b32_key.as_str())?;

                // make sure to zero out the b32_key
                b32_key.zeroize();
            }
        }

        Ok(())
    }

    pub fn delete(
        &self,
        mut writer: &mut rkv::Writer<SafeModeRwTransaction>,
        store: &SingleStore<SafeModeDatabase>,
    ) -> AppResult<()> {
        let id = self.get_id();

        delete_from_id(&id, &mut writer, store)
    }
}
