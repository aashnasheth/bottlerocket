mod error;
mod keys;
mod root;
mod s3;
mod shared;

use error::Result;
use log::info;
use pubsys_config::InfraConfig;
use sha2::{Digest, Sha512};
use shared::KeyRole;
use simplelog::{Config as LogConfig, LevelFilter, SimpleLogger};
use snafu::{OptionExt, ResultExt};
use std::path::{Path, PathBuf};
use std::{fs, process};
use structopt::StructOpt;
use tokio::runtime::Runtime;
use url::Url;

//   =^..^=   =^..^=   =^..^=  SUB-COMMAND STRUCTS  =^..^=   =^..^=   =^..^=

#[derive(Debug, StructOpt)]
#[structopt(setting = clap::AppSettings::DeriveDisplayOrder)]
struct Args {
    #[structopt(global = true, long, default_value = "INFO")]
    log_level: LevelFilter,

    // Path to Infra.toml  (NOTE: must be specified before subcommand)
    #[structopt(long, parse(from_os_str))]
    infra_config_path: PathBuf,

    #[structopt(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, StructOpt)]
#[structopt(setting = clap::AppSettings::DeriveDisplayOrder)]
struct CreateInfraArgs {
    #[structopt(long)]
    root_role_path: PathBuf,
}

#[derive(Debug, StructOpt)]
enum SubCommand {
    CheckInfraLock,
    CreateInfra(CreateInfraArgs),
}

//  =^..^=   =^..^=   =^..^=  MAIN METHODS  =^..^=   =^..^=   =^..^=

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    // Parse and store the args passed to the program
    let args = Args::from_args();

    SimpleLogger::init(args.log_level, LogConfig::default()).context(error::Logger)?;

    match args.subcommand {
        SubCommand::CheckInfraLock => {
            let rt = Runtime::new().context(error::Runtime)?;
            rt.block_on(async { check_infra_lock(&args.infra_config_path).await })
        }
        SubCommand::CreateInfra(ref run_task_args) => {
            let rt = Runtime::new().context(error::Runtime)?;
            rt.block_on(async {
                create_infra(&args.infra_config_path, &run_task_args.root_role_path).await
            })
        }
    }
}

async fn check_infra_lock(toml_path: &Path) -> Result<()> {
    // TODO: implement (coming in next PR)
    println!("Successfully in check_infra_method!");
    Ok(())
}

/// Automates setting up infrastructure for a custom TUF repo
async fn create_infra(toml_path: &Path, root_role_path: &Path) -> Result<()> {
    info!("Parsing Infra.toml...");
    let mut infra_config = InfraConfig::from_path(toml_path).context(error::Config)?;
    let repos = infra_config
        .repo
        .as_mut()
        .context(error::MissingConfig { missing: "repo" })?;

    for (repo_name, repo_config) in repos.iter_mut() {
        // Step 0: Grabbing key variables (and throwing errors if not specified)
        let s3_stack_name =
            repo_config
                .file_hosting_config_name
                .as_ref()
                .context(error::MissingConfig {
                    missing: "file_hosting_config_name",
                })?;
        let mut s3_info = infra_config
            .aws
            .as_mut()
            .context(error::MissingConfig { missing: "aws" })?
            .s3
            .as_mut()
            .context(error::MissingConfig { missing: "aws.s3" })?
            .get_mut(s3_stack_name)
            .context(error::MissingConfig {
                missing: format!("aws.s3 config with name {}", s3_stack_name),
            })?;
        let s3_region = s3_info.region.as_ref().context(error::MissingConfig {
            missing: format!("region for '{}' s3 config", s3_stack_name),
        })?;
        let vpcid = s3_info
            .vpc_endpoint_id
            .as_ref()
            .context(error::MissingConfig {
                missing: format!("vpc_endpoint_id for '{}' s3 config", s3_stack_name),
            })?;
        let prefix = s3::format_prefix(&s3_info.s3_prefix);
        let signing_keys = repo_config
            .signing_keys
            .as_mut()
            .context(error::MissingConfig {
                missing: format!("signing_keys for '{}' repo config", repo_name),
            })?;
        let root_keys = repo_config
            .root_keys
            .as_mut()
            .context(error::MissingConfig {
                missing: format!("root_keys for '{}' repo config", repo_name),
            })?;
        keys::check_signing_key_config(signing_keys)?;
        keys::check_signing_key_config(root_keys)?;
        root::check_root(root_role_path)?;

        // Step 1: Create S3 Bucket
        info!("Creating S3 bucket...");
        let (s3_stack_arn, bucket_name, bucket_url) =
            s3::create_s3_bucket(s3_region, s3_stack_name).await?;
        // Set output variables
        s3_info.stack_arn = Some(s3_stack_arn);
        s3_info.bucket_name = Some(bucket_name.clone());

        // Step 2: Add Bucket Policy to newly created bucket
        s3::add_bucket_policy(s3_region, &bucket_name, &prefix, vpcid).await?;

        // Step 3: Create root + publication keys
        info!("Creating KMS Keys...");
        keys::create_keys(signing_keys).await?;
        keys::create_keys(root_keys).await?;

        // Step 4: Create and populate (add/sign) root.json
        info!("Creating and signing root.json...");
        root::create_root(&root_role_path)?;
        // Add keys (for both roles)
        root::add_keys(
            signing_keys,
            &KeyRole::Publication,
            repo_config
                .pub_key_threshold
                .as_ref()
                .context(error::MissingConfig {
                    missing: format!("pub_key_threshold for '{}' repo config", repo_name),
                })?,
            &root_role_path.display().to_string(),
        )?;
        root::add_keys(
            root_keys,
            &KeyRole::Root,
            repo_config
                .root_key_threshold
                .as_ref()
                .context(error::MissingConfig {
                    missing: format!("root_key_threshold for '{}' repo config", repo_name),
                })?,
            &root_role_path.display().to_string(),
        )?;
        // Sign root with all root keys
        root::sign_root(root_keys, &root_role_path.display().to_string())?;

        // Step 5: Upload root.json
        info!("Uploading root.json to S3 bucket...");
        s3::upload_file(s3_region, &bucket_name, &prefix, root_role_path).await?;

        // Step 6: Update output paramters if not already set
        if repo_config.metadata_base_url.is_none() {
            repo_config.metadata_base_url = Some(
                Url::parse(format!("{}{}/metadata/", &bucket_url, prefix).as_str())
                    .context(error::ParseUrl { input: &bucket_url })?,
            );
        }
        if repo_config.targets_url.is_none() {
            repo_config.targets_url = Some(
                Url::parse(format!("{}{}/targets/", &bucket_url, prefix).as_str())
                    .context(error::ParseUrl { input: &bucket_url })?,
            );
        }
        if repo_config.root_role_url.is_none() {
            repo_config.root_role_url = Some(
                Url::parse(format!("{}{}/root.json", &bucket_url, prefix).as_str())
                    .context(error::ParseUrl { input: &bucket_url })?,
            );

            let root_role_data = fs::read_to_string(&root_role_path).context(error::FileRead {
                path: root_role_path,
            })?;
            let mut d = Sha512::new();
            d.update(&root_role_data);
            let digest = hex::encode(d.finalize());
            repo_config.root_role_sha512 = Some(digest);
        }
    }

    //Step 7: Generate Infra.lock
    info!("Writing Infra.lock...");
    let yaml_string = serde_yaml::to_string(&infra_config).context(error::InvalidYaml)?;
    fs::write(
        toml_path
            .parent()
            .context(error::Parent { path: toml_path })?
            .join("Infra.lock"),
        yaml_string,
    )
    .context(error::FileWrite { path: toml_path })?;

    info!("Complete!");
    Ok(())
}

//  =^..^=   =^..^=   =^..^=  TESTS  =^..^=   =^..^=   =^..^=

#[cfg(test)]
mod tests {
    use super::{fs, shared, InfraConfig};

    #[test]
    fn toml_yaml_conversion() {
        let test_toml_path = format!(
            "{}/test_tomls/toml_yaml_conversion.toml",
            shared::getenv("CARGO_MANIFEST_DIR").unwrap()
        );
        let toml_struct = InfraConfig::from_path(&test_toml_path).unwrap();
        let yaml_string = serde_yaml::to_string(&toml_struct).expect("Could not write to file!");

        let test_yaml_path = format!(
            "{}/test_tomls/toml_yaml_conversion.yml",
            shared::getenv("CARGO_MANIFEST_DIR").unwrap()
        );
        fs::write(&test_yaml_path, &yaml_string).expect("Could not write to file!");
        let decoded_yaml = InfraConfig::from_lock_path(&test_yaml_path).unwrap();

        assert_eq!(toml_struct, decoded_yaml);
    }
}
