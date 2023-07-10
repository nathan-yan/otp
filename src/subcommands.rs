use std::{
    error::Error,
    io::{stdout, Write},
    num::NonZeroU64,
    time::{Duration, Instant},
};

use crate::{
    app_otp::{default_true, default_ts, AppOtp},
    build_id,
    error::AppError,
    hotp, parser, AppResult, EOTP_REFRESH_DELAY, SERVICE_NAME,
};
use colored::Colorize;
use copypasta::{ClipboardContext, ClipboardProvider};
use crossterm::{
    cursor,
    event::{self, poll},
    terminal, ExecutableCommand,
};
use inquire::validator::Validation;
use libsodium_sys::{
    crypto_secretbox_KEYBYTES, crypto_secretbox_MACBYTES, crypto_secretbox_NONCEBYTES,
    crypto_secretbox_easy, crypto_secretbox_keygen, crypto_secretbox_open_easy,
};
use parser::{DeleteArgs, NewArgs, ShowArgs};
use rkv::{
    backend::{SafeModeDatabase, SafeModeEnvironment, SafeModeRwTransaction},
    Rkv, SingleStore,
};
use rpassword::read_password;
use secrets::traits::AsContiguousBytes;
use serde_json::{from_str, to_string, Value};

fn create_secret_from_stdin() -> AppResult<hotp::Secret> {
    print!("Secret: ");
    stdout().flush()?;

    let unsecured_b32 = read_password()?;

    // unsecured_secret is a vec<u8>
    // the backing data for the vec is stored on the heap and won't be moved
    // so we create a secret vec from the unsecured backing vec, and zero out the unsecured vec
    hotp::Secret::try_from_b32(unsecured_b32).ok_or(AppError::GenericError(
        "Secret must be a valid base32 string.".to_string(),
    ))
}

pub fn delete_from_id(
    id: &str,
    mut writer: &mut rkv::Writer<SafeModeRwTransaction>,
    store: &SingleStore<SafeModeDatabase>,
) -> AppResult<()> {
    let keyring_entry = keyring::Entry::new(SERVICE_NAME, id)?;
    keyring_entry.delete_password()?;

    // we only want to delete the entry from the kv store if we've successfully
    // deleted the keyring entry, which prevents us from having orphaned secrets
    // in the keyring without a reference to them.
    store.delete(&mut writer, id)?;

    Ok(())
}

fn handle_delete_result(id: &str, res: AppResult<()>) {
    match res {
        Ok(_) => println!("{}", format!("Deleted {}.", id).green()),
        Err(e) => {
            let src = e.source().unwrap();

            println!(
                "{}",
                format!("Possibly deleted {}; an error occurred: {}", id, src).yellow()
            );
        }
    }
}

pub fn format_metadata(metadata: &hotp::Metadata, selected: bool) -> String {
    let mut acc = String::new();

    if selected {
        acc.push_str(format!("{}", metadata.name.yellow().bold()).as_str());
    } else {
        acc.push_str(format!("{}", metadata.name.yellow().bold()).as_str());
    }

    match metadata.user {
        Some(ref username) => acc.push_str(format!(" ({})\n", username).as_str()),
        None => acc.push_str("\n"),
    }

    metadata.issuer.as_ref().and_then(|i| {
        acc.push_str(
            format!("Issuer: {}", i)
                .truecolor(130, 130, 130)
                .to_string()
                .as_str(),
        );
        acc.push('\n');
        Some(())
    });

    metadata
        .description
        .as_ref()
        .and_then(|i| Some(acc.push_str(format!("Description: {}\n", i).as_str())));

    if acc.len() > 0 {
        acc.pop();
    }

    return acc;
}

fn stream_otps(otps: &mut Vec<AppOtp>) -> AppResult<()> {
    let mut stdout = stdout();

    stdout.execute(cursor::Hide)?;
    terminal::enable_raw_mode()?;

    let codes = b"abcdefghijklmnoprstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let mut last_refreshed = Instant::now() - Duration::from_millis(1000);
    let mut refresh = false;
    let refresh_interval = Duration::from_millis(1000);

    let mut selected_code = ' ';
    let mut selected_idx = None;

    loop {
        let elapsed = last_refreshed.elapsed();

        if elapsed > refresh_interval || refresh {
            selected_idx = None;
            last_refreshed = Instant::now();
            refresh = false;

            //stdout.execute(cursor::MoveTo(current_pos.0, current_pos.1))?;
            stdout.execute(terminal::Clear(terminal::ClearType::FromCursorDown))?;
            writeln!(stdout, "")?;

            let mut line_count = 1;
            for (idx, otp) in otps.iter().enumerate() {
                let mut otp_string = textwrap::indent(
                    otp.to_string(false, true).replace("\n", "\r\n").as_str(),
                    "     ",
                );
                line_count += otp_string.lines().count() + 1;

                let label = codes[idx] as char;

                if label == selected_code {
                    selected_idx = Some(idx);
                    otp_string = textwrap::indent(
                        otp.to_string(true, true).replace("\n", "\r\n").as_str(),
                        "│    ",
                    );
                    otp_string.replace_range(4..6, format!("{}:", label).as_str());
                } else {
                    otp_string.replace_range(2..4, format!("{}:", label).as_str());
                }

                writeln!(stdout, "{}\r\n", otp_string)?;
            }

            stdout.execute(cursor::MoveUp(line_count as u16))?;
        }

        let poll_time = refresh_interval
            .checked_sub(elapsed)
            .unwrap_or(Duration::from_millis(0));

        if poll(poll_time)? {
            match event::read()? {
                event::Event::Key(event) => match event.code {
                    event::KeyCode::Char('q') => {
                        break;
                    }
                    event::KeyCode::Enter => {
                        if let Some(idx) = selected_idx {
                            if let AppOtp::Eotp {
                                ref mut eotp,
                                hidden,
                                last_incremented,
                            } = otps.get_mut(idx).unwrap()
                            {
                                if last_incremented.elapsed()
                                    > Duration::from_secs(EOTP_REFRESH_DELAY)
                                {
                                    eotp.increment_counter();
                                    *last_incremented = Instant::now();
                                    *hidden = false;
                                    refresh = true;
                                }
                            }
                        }
                    }
                    event::KeyCode::Char(' ') => {
                        if let Some(idx) = selected_idx {
                            let otp = otps.get(idx).unwrap().get_otp_string();
                            let mut ctx = ClipboardContext::new().unwrap();
                            ctx.set_contents(otp).unwrap();
                        }
                    }
                    event::KeyCode::Char(c) => {
                        selected_code = c;
                        refresh = true
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }

    stdout.execute(cursor::Show)?;
    terminal::disable_raw_mode()?;

    Ok(())
}

pub fn new_subcommand(
    args: NewArgs,
    env: &Rkv<SafeModeEnvironment>,
    store: &SingleStore<SafeModeDatabase>,
) -> AppResult<()> {
    let id = build_id(&args.name, &args.user);

    {
        let reader = env.read().unwrap();
        if store.get(&reader, id.as_str()).unwrap().is_some() {
            return Err(AppError::GenericError(format!("The one time password `{}` already exists. If you would like to delete the existing OTP, use `otp delete`", id)));
        }
    }

    // prompt the user for the OTP secret
    let secret = create_secret_from_stdin()?;

    let metadata = hotp::Metadata {
        name: args.name,
        user: args.user,
        issuer: args.issuer,
        description: args.description,
    };

    let length = args.length.unwrap_or_default();

    let hotp = hotp::Hotp::new(metadata, length, secret);

    let otp;
    if args.event {
        let eotp = hotp::Eotp::new(hotp, 0);
        otp = AppOtp::Eotp {
            eotp,
            hidden: default_true(),
            last_incremented: default_ts(),
        };
    } else {
        let totp = hotp::Totp::new(hotp, NonZeroU64::new(args.interval).unwrap());
        otp = AppOtp::Totp(totp);
    }

    let mut writer = env.write()?;
    otp.write(&mut writer, store, true)?;

    println!("{}", format!("Wrote to {}. Cleaning up...", id).green());

    Ok(writer.commit()?)
}

pub fn show_subcommand(
    args: ShowArgs,
    env: &Rkv<SafeModeEnvironment>,
    store: &SingleStore<SafeModeDatabase>,
) -> AppResult<()> {
    let reader = env.read().unwrap();
    let otps = store.iter_start(&reader)?;

    let mut matches = otps
        .filter_map(|otp| {
            if let Ok((_, value)) = otp {
                let otp = AppOtp::try_from(&value);
                if otp.is_err() {
                    return None;
                }

                let otp = otp.unwrap();

                let name = match args.name {
                    None => return Some(otp),
                    Some(ref name) => name.as_str(),
                };

                if otp.get_metadata().name.as_str() == name {
                    return Some(otp);
                }
            }

            None
        })
        .collect::<Vec<AppOtp>>();

    if matches.len() == 0 {
        println!(
            "{}",
            "No one time passwords to show.".truecolor(150, 150, 150)
        );
    } else {
        stream_otps(&mut matches)?;
    }

    Ok(())
}

pub fn delete_subcommand(
    args: DeleteArgs,
    env: &Rkv<SafeModeEnvironment>,
    store: &SingleStore<SafeModeDatabase>,
) -> AppResult<()> {
    let mut writer = env.write().unwrap();
    let reader = env.read().unwrap();

    let otps = store.iter_start(&reader)?;
    let mut candidates = Vec::new();

    for otp in otps {
        if otp.is_err() {
            continue;
        }

        let (key, value) = otp.unwrap();
        let key_str = String::from_utf8_lossy(key);
        let otp = AppOtp::try_from(&value);

        // there needs to be a way of deleting malformed json blobs
        // since we can't access the user information, just check if the
        // key exactly matches the passed in name argument
        if otp.is_err() {
            if key_str == args.name.to_lowercase() {
                candidates.push(key_str);
            }
        } else {
            let otp = otp.unwrap();
            let metadata = otp.get_metadata();
            if metadata.name == args.name.to_lowercase()
                && (args.user.is_none() || metadata.user == args.user)
            {
                candidates.push(key_str);
            }
        }
    }

    let id = build_id(&args.name.yellow().to_string(), &args.user);

    match candidates.len() {
        0 => {
            return Err(AppError::GenericError(format!(
                "Could not find one time password with name {}.",
                id
            )))
        }
        1 => {
            // delete the single one time password
            let confirm =
                inquire::Confirm::new(format!("Are you sure you want to delete {}?", id).as_str())
                    .with_default(false)
                    .prompt()
                    .unwrap();

            if !confirm {
                println!("Aborting...");
                return Ok(());
            }

            let res = delete_from_id(candidates[0].as_ref(), &mut writer, store);
            handle_delete_result(candidates[0].as_ref(), res);
        }
        _ => {
            println!("There are multiple one time passwords with name {}, which do you want to delete?\n", id);
            for (idx, candidate) in candidates.iter().enumerate() {
                println!("    {}: {}", idx, candidate);
            }

            println!("");
            let response = inquire::Text::new("")
                .with_help_message("Type a comma separated list of numbers")
                .prompt()
                .map_err(|err| {
                    AppError::GenericError(format!("Could not process user response: {}.", err))
                })?;

            if response == "" {
                println!("Aborting...");
                return Ok(());
            }

            let indices = response
                .split(",")
                .map(|s| s.trim().parse::<usize>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    AppError::GenericError(
                        "Response must be a comma separated list of numbers.".to_string(),
                    )
                })?;

            let mut prompt = String::from("Are you sure you want to delete ");
            for idx in &indices {
                if *idx < candidates.len() {
                    prompt.push_str(candidates[*idx].as_ref());
                    prompt.push_str(", ");
                }
            }

            // fencepost
            prompt.pop();
            prompt.pop();
            prompt.push_str("?");

            let confirm = inquire::Confirm::new(&prompt)
                .with_default(false)
                .prompt()
                .unwrap();

            if !confirm {
                println!("Aborting...");
                return Ok(());
            }

            for idx in &indices {
                if *idx < candidates.len() {
                    let res = delete_from_id(candidates[*idx].as_ref(), &mut writer, store);
                    handle_delete_result(candidates[*idx].as_ref(), res);
                }
            }
        }
    }

    writer.commit()?;
    Ok(())
}

pub fn export_subcommand(
    env: &Rkv<SafeModeEnvironment>,
    store: &SingleStore<SafeModeDatabase>,
) -> AppResult<()> {
    let reader = env.read().unwrap();

    let otps = store.iter_start(&reader)?;

    let mut app_otps = Vec::new();

    for otp in otps {
        let Ok((_, value)) = otp else { continue; };
        let Ok(otp) = AppOtp::try_from(&value) else {continue;};
        let Ok(otp_json) = otp.export() else {continue;};

        app_otps.push(otp_json);
    }

    let data_json = format!("{}", to_string(&app_otps)?);

    let key = [0u8; crypto_secretbox_KEYBYTES as usize];
    unsafe {
        crypto_secretbox_keygen(&key as *const u8 as *mut u8);

        let plaintext = data_json.as_bytes();

        let ciphertext = [65u8; 2048];
        let nonce = [4u8; crypto_secretbox_NONCEBYTES as usize];

        // TODO: Use res for error reporting
        let _ = crypto_secretbox_easy(
            &ciphertext as *const u8 as *mut u8,
            plaintext.as_u8_ptr(),
            plaintext.len() as u64,
            &nonce as *const u8,
            &key as *const u8,
        );
        std::fs::write(
            "./otp.encrypted",
            ciphertext
                .as_bytes()
                .split_at(plaintext.len() + crypto_secretbox_MACBYTES as usize)
                .0,
        )?;

        println!(
            "Your key is: {}\n\n{}",
            base32::encode(base32::Alphabet::RFC4648 { padding: false}, key.as_slice()).yellow(), "When you are done transferring your one time passwords, delete all copies of the encrypted export file.".red()
        );
    }

    Ok(())
}

pub fn import_subcommand(
    env: &Rkv<SafeModeEnvironment>,
    store: &SingleStore<SafeModeDatabase>,
) -> AppResult<()> {
    let mut writer = env.write().unwrap();
    let contents = std::fs::read("./otp.encrypted")?;

    let validator = |input: &str| {
        if base32::decode(base32::Alphabet::RFC4648 { padding: false }, input).is_none() {
            Ok(Validation::Invalid(
                "Please enter a valid Base32 string".into(),
            ))
        } else {
            Ok(Validation::Valid)
        }
    };

    let key = inquire::Text::new("Enter key:")
        .with_validator(validator)
        .prompt()
        .map_err(|_| AppError::GenericError("Failed to get key from user.".into()))?;

    let key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, key.as_str()).unwrap();
    let nonce = [4u8; crypto_secretbox_NONCEBYTES as usize];

    let mut plaintext = [0u8; 2048];
    unsafe {
        crypto_secretbox_open_easy(
            secrets::traits::Bytes::as_mut_u8_ptr(&mut plaintext),
            contents.as_u8_ptr(),
            contents.len() as u64,
            secrets::traits::Bytes::as_u8_ptr(&nonce),
            key.as_u8_ptr(),
        );
    }

    let plaintext = &String::from_utf8_lossy(&plaintext).to_string()
        [..contents.len() - crypto_secretbox_MACBYTES as usize];
    let json = from_str::<Value>(plaintext)?;

    for otp_json in json.as_array().unwrap() {
        AppOtp::import(to_string(&otp_json)?.as_str(), &mut writer, &store)?;
    }

    Ok(writer.commit()?)
}
