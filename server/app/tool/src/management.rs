use crate::management_api::Tee;
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::prelude::*;
use std::path::Path;

use crate::management_api::management_service_client::ManagementServiceClient;
use crate::management_api::{
    GetPolicyRequest, GetPolicyResponse, GetReferenceDataRequest, GetReferenceDataResponse,
    RestoreDefaultPolicyRequest, RestoreDefaultReferenceDataRequest, SetPolicyRequest,
    SetReferenceDataRequest,
};

const MANAGEMENT_SOCKET: &str = "127.0.0.1:3001";

impl Tee {
    fn from_str(tee: &str) -> Result<Tee> {
        match tee {
            "sgx" => Ok(Tee::Sgx),
            "tdx" => Ok(Tee::Tdx),
            "sev-snp" => Ok(Tee::SevSnp),
            "sample" => Ok(Tee::Sample),
            _ => Err(anyhow!("TEE: {} is not supported", tee)),
        }
    }
}

fn store(dir: &Path, name: &str, content: &str) -> Result<()> {
    let file = dir.join(name);
    fs::File::create(file.as_path())
        .context(anyhow!("create file failed"))?
        .write_all(content.as_bytes())
        .context(anyhow!("write failed"))
}

pub async fn set_policy_cmd(
    tee: Option<&str>,
    file: Option<&str>,
    socket: Option<&str>,
) -> Result<()> {
    let socket = socket.unwrap_or(MANAGEMENT_SOCKET);
    if tee.is_none() {
        return Err(anyhow!("[--tee <TEE>] must be specified."));
    }
    if file.is_none() {
        return Err(anyhow!("[--policy <POLICY>] must be specified."));
    }
    let tee = tee.unwrap();
    let policy = fs::read_to_string(file.unwrap()).context(anyhow!("Read policy error"))?;

    let request = SetPolicyRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
        content: policy.into_bytes(),
    };

    let mut client = ManagementServiceClient::connect(format!("http://{}", socket)).await?;
    client.set_policy(request).await?;
    Ok(())
}

pub async fn set_reference_data_cmd(
    tee: Option<&str>,
    file: Option<&str>,
    socket: Option<&str>,
) -> Result<()> {
    let socket = socket.unwrap_or(MANAGEMENT_SOCKET);
    if tee.is_none() {
        return Err(anyhow!("[--tee <TEE>] must be specified."));
    }
    if file.is_none() {
        return Err(anyhow!(
            "[--reference-data <REFERENCE_DATA>] must be specified."
        ));
    }
    let reference_data =
        fs::read_to_string(file.unwrap()).context(anyhow!("Read reference data error"))?;

    let request = SetReferenceDataRequest {
        tee: Tee::from_str(tee.unwrap())? as i32,
        user: None,
        content: reference_data.into_bytes(),
    };

    let mut client = ManagementServiceClient::connect(format!("http://{}", socket)).await?;
    client.set_reference_data(request).await?;
    Ok(())
}

pub async fn get_policy_cmd(tee: Option<&str>, socket: Option<&str>) -> Result<()> {
    let socket = socket.unwrap_or(MANAGEMENT_SOCKET);
    let tee = tee.unwrap_or("sample");

    let request = GetPolicyRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(format!("http://{}", socket)).await?;
    let response: GetPolicyResponse = client.get_policy(request).await?.into_inner();
    let policy = String::from_utf8(response.content).unwrap();
    info!("{}", &policy);
    store(Path::new("./"), "Policy.rego", &policy)?;

    Ok(())
}

pub async fn get_reference_data_cmd(tee: Option<&str>, socket: Option<&str>) -> Result<()> {
    let socket = socket.unwrap_or(MANAGEMENT_SOCKET);
    let tee = tee.unwrap_or("sample");

    let request = GetReferenceDataRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(format!("http://{}", socket)).await?;
    let response: GetReferenceDataResponse = client.get_reference_data(request).await?.into_inner();
    let reference_data = String::from_utf8(response.content).unwrap();
    info!("{}", &reference_data);
    store(Path::new("./"), "Reference_data.json", &reference_data)?;

    Ok(())
}

pub async fn restore_default_policy_cmd(tee: Option<&str>, socket: Option<&str>) -> Result<()> {
    let socket = socket.unwrap_or(MANAGEMENT_SOCKET);
    if tee.is_none() {
        return Err(anyhow!("[--tee <TEE>] must be specified."));
    }

    let request = RestoreDefaultPolicyRequest {
        tee: Tee::from_str(tee.unwrap())? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(format!("http://{}", socket)).await?;
    client.restore_default_policy(request).await?;
    Ok(())
}

pub async fn restore_default_reference_data_cmd(
    tee: Option<&str>,
    socket: Option<&str>,
) -> Result<()> {
    let socket = socket.unwrap_or(MANAGEMENT_SOCKET);
    if tee.is_none() {
        return Err(anyhow!("[--tee <TEE>] must be specified."));
    }

    let request = RestoreDefaultReferenceDataRequest {
        tee: Tee::from_str(tee.unwrap())? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(format!("http://{}", socket)).await?;
    client.restore_default_reference_data(request).await?;
    Ok(())
}
