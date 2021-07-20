use rusoto_cloudformation::{CloudFormation, CloudFormationClient, CreateStackInput};
use rusoto_core::Region;
use rusoto_s3::{
    GetBucketPolicyRequest, PutBucketPolicyRequest, PutObjectRequest, S3Client, StreamingBody, S3,
};
use snafu::{OptionExt, ResultExt};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::str::FromStr;

use super::{error, shared, Result};

pub fn format_prefix(prefix: &String) -> String {
    let formatted = {
        if prefix.starts_with('/') {
            return prefix.to_string();
        }
        format!("/{}", prefix)
    };
    if formatted.ends_with('/') {
        formatted[..formatted.len() - 1].to_string();
    }
    if formatted.ends_with("/*") {
        formatted[..formatted.len() - 2].to_string();
    }
    formatted
}

/// Creates a *private* S3 Bucket using a CloudFormation template
/// Input: The region in which the bucket will be created and the name of the bucket
/// Output: The stack_arn of the bucket created (will be added as a field to Infra.lock)
pub async fn create_s3_bucket(
    region: &String,
    stack_name: &String,
) -> Result<(String, String, String)> {
    // IN-FUTURE: Add support for accomodating pre-existing buckets (skip this creation process)
    let cfn_client = CloudFormationClient::new(
        Region::from_str(region).context(error::ParseRegion { what: region })?,
    );
    let cfn_filepath: PathBuf = format!(
        "{}/infrasys/cloudformation-templates/s3_setup.yml",
        shared::getenv("BUILDSYS_TOOLS_DIR")?
    )
    .into();
    let cfn_template =
        fs::read_to_string(&cfn_filepath).context(error::FileRead { path: cfn_filepath })?;
    let stack_result = cfn_client
        .create_stack(CreateStackInput {
            stack_name: stack_name.clone(),
            template_body: Some(cfn_template.clone()),
            ..Default::default()
        })
        .await
        .context(error::CreateStack { stack_name, region })?;
    // We don't have to wait for successful stack creation to grab the stack ARN
    let stack_arn = stack_result
        .clone()
        .stack_id
        .context(error::ParseResponse {
            what: "stack_id",
            resource_name: stack_name,
        })?;

    // Grab the StackOutputs to get the Bucketname and BucketURL
    let output_array = shared::get_stack_outputs(&cfn_client, &stack_name, region).await?;
    let bucket_name = output_array[0]
        .output_value
        .as_ref()
        .context(error::ParseResponse {
            what: "outputs[0].output_value (bucket name)",
            resource_name: stack_name,
        })?
        .to_string();
    let bucket_url = output_array[1]
        .output_value
        .as_ref()
        .context(error::ParseResponse {
            what: "outputs[1].output_value (bucket url)",
            resource_name: stack_name,
        })?
        .to_string();

    Ok((stack_arn, bucket_name, bucket_url))
}

/// Adds a BucketPolicy allowing GetObject access to a specified VPC
/// Input: Region, Name of bucket, which prefix root.json should be put under, and vpcid
/// Note that the prefix parameter must have the format "/<folder>/*" and the bucket name "<name>"
/// Output: Doesn't need to save any metadata from this action  
pub async fn add_bucket_policy(
    region: &String,
    bucket_name: &String,
    prefix: &String,
    vpcid: &String,
) -> Result<()> {
    // Get old policy
    let s3_client =
        S3Client::new(Region::from_str(region).context(error::ParseRegion { what: region })?);
    let mut current_bp: serde_json::Value = match s3_client
        .get_bucket_policy(GetBucketPolicyRequest {
            bucket: bucket_name.clone(),
            expected_bucket_owner: None,
        })
        .await
    {
        Ok(output) => serde_json::from_str(&output.policy.context(error::ParseResponse {
            what: "policy",
            resource_name: bucket_name,
        })?)
        .context(error::InvalidJson {
            what: format!("retrieved bucket policy for {}", &bucket_name),
        })?,

        Err(..) => serde_json::from_str(
            r#"{"Version": "2008-10-17",
                     "Statement": []}"#,
        )
        .context(error::InvalidJson {
            what: format!("new bucket policy for {}", &bucket_name),
        })?,
    };

    // Create a new policy
    let new_bucket_policy = serde_json::from_str(&format!(
        "{{
                       \"Effect\": \"Allow\",
                        \"Principal\": \"*\",
                        \"Action\": \"s3:GetObject\",
                        \"Resource\": \"arn:aws:s3:::{}{}/*\",
                        \"Condition\": {{
                            \"StringEquals\": {{
                                \"aws:sourceVpce\": \"{}\"
                            }}
                        }}
                    }}",
        bucket_name, prefix, vpcid
    ))
    .context(error::InvalidJson {
        what: format!("new bucket policy for {}", &bucket_name),
    })?;

    // Append new policy onto old one
    current_bp
        .get_mut("Statement")
        .context(error::GetPolicyStatement { bucket_name })?
        .as_array_mut()
        .context(error::GetPolicyStatement { bucket_name })?
        .push(new_bucket_policy);

    // Push the new policy as a string
    s3_client
        .put_bucket_policy(PutBucketPolicyRequest {
            bucket: bucket_name.clone(),
            policy: serde_json::to_string(&current_bp).context(error::InvalidJson {
                what: format!("new bucket policy for {}", &bucket_name),
            })?,
            ..Default::default()
        })
        .await
        .context(error::PutPolicy { bucket_name })?;

    Ok(())
}

/// Uploads root.json to S3 Bucket (automatically creates the folder that the bucket policy was scoped to or will simply add to it)
/// Input: Region, Name of bucket, which prefix root.json should be put under, and path to the S3 bucket CFN template
/// Note that the prefix parameter must have the format "/<folder>" and the bucket name "<name>"
/// Output: Doesn't need to save any metadata from this action
pub async fn upload_file(
    region: &String,
    bucket_name: &String,
    prefix: &String,
    file_path: &PathBuf,
) -> Result<()> {
    let s3_client =
        S3Client::new(Region::from_str(region).context(error::ParseRegion { what: region })?);

    // File --> Bytes
    let mut file = File::open(file_path).context(error::FileOpen { path: file_path })?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context(error::FileRead { path: file_path })?;

    s3_client
        .put_object(PutObjectRequest {
            bucket: format!("{}{}", bucket_name, prefix),
            key: "root.json".to_string(), // hard-coded file name
            body: Some(StreamingBody::from(buffer)),
            ..Default::default()
        })
        .await
        .context(error::PutObject { bucket_name })?;

    Ok(())
}
