use super::{error, KeyRole, Result};
use log::{trace, warn};
use pubsys_config::SigningKeyConfig;
use rusoto_core::Region;
use snafu::{ensure, OptionExt, ResultExt};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// The tuftool macro wraps Command to simplify calls to tuftool, adding region functionality.
macro_rules! tuftool {
    // We use variadic arguments to wrap a format! call so the user doesn't need to call format!
    // each time. tuftool root` always requires the path to root.json so there's always at least
    // one.
    ($region:expr, $format_str:expr, $($format_arg:expr),*) => {
        let arg_str = format!($format_str, $($format_arg),*);
        trace!("tuftool arg string: {}", arg_str);
        let args = shell_words::split(&arg_str).context(error::CommandSplit { command: &arg_str })?;
        trace!("tuftool split args: {:#?}", args);

        let status = Command::new("tuftool")
            .args(args)
            .env("AWS_REGION", $region)
            .status()
            .context(error::TuftoolSpawn)?;

        ensure!(status.success(), error::TuftoolResult {
            command: arg_str,
            code: status.code().map(|i| i.to_string()).unwrap_or_else(|| "<unknown>".to_string())
        });
    }
}

pub fn check_root(root_role_path: &PathBuf) -> Result<()> {
    if root_role_path.is_file() {
        warn!("Please delete file at {}", root_role_path.display());
        error::FileExists {
            path: root_role_path,
        }
        .fail()?
    }
    Ok(())
}

/// Creates the directory where root.json will live and creates root.json itself according to details specified in root-role-path
pub fn create_root(root_role_path: &PathBuf) -> Result<()> {
    // Make /roles and /keys directories, if they don't exist, so we can write generated files.
    // If root file already exists, will be overwritten
    let role_dir = root_role_path.parent().context(error::Path {
        path: root_role_path,
        thing: "root role",
    })?;
    fs::create_dir_all(role_dir).context(error::Mkdir { path: role_dir })?;
    // Initialize root
    tuftool!(
        Region::default().name(),
        "root init '{}'",
        root_role_path.display()
    );
    tuftool!(
        Region::default().name(),
        // TODO: expose expiration date as a configurable parameter
        "root expire '{}' 'in 52 weeks'",
        root_role_path.display()
    );
    Ok(())
}

/// Adds keys to root.json according to key type  
pub fn add_keys(
    signing_key_config: &mut SigningKeyConfig,
    role: &KeyRole,
    threshold: &String,
    filepath: &String,
) -> Result<()> {
    match signing_key_config {
        SigningKeyConfig::file { .. } => (),
        SigningKeyConfig::kms { key_id, config, .. } => add_keys_kms(
            &config
                .as_ref()
                .context(error::MissingConfig {
                    missing: "config field for a kms key",
                })?
                .available_keys,
            role,
            threshold,
            filepath,
            key_id,
        )?,
        SigningKeyConfig::ssm { .. } => (),
    }
    Ok(())
}

/// Adds KMSKeys to root.json given root or publication type
/// Input: available-keys (keys to sign with), role (root or publication), threshold for role, filepath for root.JSON,
/// mutable key_id
/// Output: in-place edit of root.json and key_id with a valid publication key
/// (If key-id is populated, it will not change. Otherwise, it will be populated with a key-id of an available key)
fn add_keys_kms(
    available_keys: &HashMap<String, String>,
    role: &KeyRole,
    threshold: &String,
    filepath: &String,
    key_id: &mut Option<String>,
) -> Result<()> {
    if (*available_keys).len()
        < (*threshold)
            .parse::<usize>()
            .context(error::ParseInt { what: threshold })?
    {
        error::InvalidThreshold {
            threshold,
            num_keys: (*available_keys).len(),
        }
        .fail()?;
    }
    match role {
        KeyRole::Root => {
            tuftool!(
                Region::default().name(),
                "root set-threshold '{}' root '{}' ",
                filepath,
                threshold
            ); // region not used
            for (keyid, region) in available_keys.iter() {
                tuftool!(
                    region,
                    "root add-key '{}' aws-kms:///'{}' --role root",
                    filepath,
                    keyid
                );
            }
        }
        KeyRole::Publication => {
            tuftool!(
                Region::default().name(),
                "root set-threshold '{}' snapshot '{}' ",
                filepath,
                threshold
            );
            tuftool!(
                Region::default().name(),
                "root set-threshold '{}' targets '{}' ",
                filepath,
                threshold
            );
            tuftool!(
                Region::default().name(),
                "root set-threshold '{}' timestamp '{}' ",
                filepath,
                threshold
            );
            for (keyid, region) in available_keys.iter() {
                tuftool!(
                region,
                "root add-key '{}' aws-kms:///'{}' --role snapshot --role targets --role timestamp",
                filepath,
                keyid
                );
            }

            // Set key_id using a publication key (if one is not already provided)
            // NOTE: We must set key_id in this method as it's the only one that differentiates roles
            // (We only want key_id to be set for publication keys, not root keys)
            if key_id.is_none() {
                *key_id = Some(
                    available_keys
                        .iter()
                        .next()
                        .context(error::KeyCreation)?
                        .0
                        .to_string(),
                );
            }
        }
    }

    Ok(())
}

/// Signs root with available_keys under root_keys (will have a different tuftool command depending on key type)
pub fn sign_root(signing_key_config: &SigningKeyConfig, filepath: &String) -> Result<()> {
    match signing_key_config {
        SigningKeyConfig::file { .. } => (),
        SigningKeyConfig::kms { config, .. } => {
            for (keyid, region) in config
                .as_ref()
                .context(error::MissingConfig {
                    missing: "KMS key details",
                })?
                .available_keys
                .iter()
            {
                tuftool!(region, "root sign '{}' -k aws-kms:///'{}'", filepath, keyid);
            }
        }
        SigningKeyConfig::ssm { .. } => (),
    }
    Ok(())
}
