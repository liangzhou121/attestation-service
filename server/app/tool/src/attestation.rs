use anyhow::{anyhow, Result};
use serde_json::json;

use crate::attestation_api::attestation_service_client::AttestationServiceClient;
use crate::attestation_api::{AttestationRequest, AttestationResponse};

pub async fn attestation_cmd(tee: &str, addr: &str) -> Result<()> {
    let tee = map_tee(tee)?;

    let request = AttestationRequest {
        evidence: sample_evidence(tee)?.into_bytes(),
    };

    let mut client = AttestationServiceClient::connect(format!("http://{}", addr)).await?;
    let response: AttestationResponse = client.attestation(request).await?.into_inner();
    let results = String::from_utf8(response.attestation_results)?;
    info!("Attestation Results:\n {}", results.clone());

    Ok(())
}

fn map_tee(tee: &str) -> Result<String> {
    let tee = match tee {
        "sample" => Ok("sample".to_string()),
        _ => Err(anyhow!("Only <sample> TEE is supported.")),
    }?;
    Ok(tee)
}

fn sample_evidence(tee: String) -> Result<String> {
    let quote = json!({
        "is_debuggable": false,
        "cpusvn": 1,
        "svn": 1
    })
    .to_string();

    let evidence = json!({
        "tee": tee,
        "quote": quote,
        "ehd": "".to_string(),
        "aad": "".to_string()
    })
    .to_string();

    Ok(evidence)
}
