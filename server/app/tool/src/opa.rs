use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::prelude::*;

use crate::management_api::files::*;
use crate::management_api::opa_service_client::OpaServiceClient;
use crate::management_api::Files;
use crate::management_api::{ConfigOpaRequest, ConfigOpaResponse};
use crate::management_api::{QueryOpaRequest, QueryOpaResponse};
use crate::management_api::{TestOpaRequest, TestOpaResponse};

pub async fn config_opa_cmd(vals: Vec<&str>, name: Names, addr: &str) -> Result<()> {
    let mut content = String::new();
    fs::File::open(vals[1])
        .context(format!("Failed to open the file named {}.", vals[1]))?
        .read_to_string(&mut content)
        .context(format!("Failed to read from the file named {}.", vals[1]))?;

    let file = Files {
        tee: map_tee(vals[0] as &str)?,
        name: name as i32,
    };

    let request = ConfigOpaRequest {
        file: Some(file),
        content: content.into_bytes(),
    };

    let mut client = OpaServiceClient::connect(format!("http://{}", addr)).await?;
    let response: ConfigOpaResponse = client.config_opa(request).await?.into_inner();
    info!(
        "set_opa_policy status is: {:?}",
        String::from_utf8(response.status).unwrap()
    );

    Ok(())
}

pub async fn query_opa_cmd(tee: &str, name: Names, addr: &str) -> Result<String> {
    let file = Files {
        tee: map_tee(tee)?,
        name: name as i32,
    };

    let request = QueryOpaRequest { file: Some(file) };

    let mut client = OpaServiceClient::connect(format!("http://{}", addr)).await?;
    let response: QueryOpaResponse = client.query_opa(request).await?.into_inner();
    let content = String::from_utf8(response.content)?;
    info!("Content:\n {}", content.clone());

    Ok(content)
}

pub async fn test_opa(args: Vec<&str>, addr: &str) -> Result<()> {
    let mut policy = String::new();
    fs::File::open(args[0])
        .context(format!("Failed to open the file named {}.", args[0]))?
        .read_to_string(&mut policy)
        .context(format!("Failed to read from the file named {}.", args[0]))?;

    let mut reference = String::new();
    fs::File::open(args[1])
        .context(format!("Failed to open the file named {}.", args[1]))?
        .read_to_string(&mut reference)
        .context(format!("Failed to read from the file named {}.", args[1]))?;

    let mut input = String::new();
    fs::File::open(args[2])
        .context(format!("Failed to open the file named {}.", args[2]))?
        .read_to_string(&mut input)
        .context(format!("Failed to read from the file named {}.", args[2]))?;

    let request = TestOpaRequest {
        policy: policy.into_bytes(),
        reference: reference.into_bytes(),
        input: input.into_bytes(),
    };

    let mut client = OpaServiceClient::connect(format!("http://{}", addr)).await?;
    let response: TestOpaResponse = client.test_opa(request).await?.into_inner();
    let content = String::from_utf8(response.status)?;
    info!("Status:\n {}", content.clone());
    Ok(())
}

fn map_tee(tee: &str) -> Result<i32> {
    let tee = match tee {
        "sgx" => Ok(Tees::Sgx),
        "tdx" => Ok(Tees::Tdx),
        "sev-snp" => Ok(Tees::SevSnp),
        "sample" => Ok(Tees::Sample),
        _ => Err(anyhow!(
            "Only <sgx>, <tdx>, <sev-snp>, and <sample> TEEs are supported."
        )),
    }? as i32;
    Ok(tee)
}
