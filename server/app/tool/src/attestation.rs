use anyhow::{anyhow, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha384};
use std::fs;

use crate::attestation_api::attestation_service_client::AttestationServiceClient;
use crate::attestation_api::{AttestationRequest, AttestationResponse};

const ATTESTATION_SOCK: &str = "127.0.0.1:3000";

fn evidence() -> Result<String> {
    let nonce: &str = "1234567890";
    let key: &str = "hduabci29e0asdadans0212nsj0e3n";

    let pubkey = json!({
        "algorithm": "".to_string(),
        "pubkey-length": "".to_string(),
        "pubkey": key.to_string()
    })
    .to_string();
    let mut hasher = Sha384::new();
    hasher.update(nonce);
    hasher.update(&pubkey);
    let hash = hasher.finalize();
    let tee_evidence = json!({
        "is_debuggable": false,
        "cpusvn": 1,
        "svn": 1,
        "report_data": base64::encode(hash)
    })
    .to_string();
    let evidence = json!({
        "nonce": nonce.to_owned(),
        "tee": "sample".to_string(),
        "tee-pubkey": pubkey,
        "tee-evidence": tee_evidence
    })
    .to_string();

    Ok(evidence)
}

pub async fn attestation_cmd(tee: Option<&str>, socket: Option<&str>) -> Result<()> {
    let socket = socket.unwrap_or(ATTESTATION_SOCK);
    let evidence = tee.map_or(evidence(), |tee| {
        fs::read_to_string(tee).context(anyhow!("Read evidence error"))
    })?;

    let request = AttestationRequest {
        evidence: evidence.into_bytes(),
        user: None,
    };

    let mut client = AttestationServiceClient::connect(format!("http://{}", socket)).await?;
    let response: AttestationResponse = client.attestation(request).await?.into_inner();
    let results = String::from_utf8(response.attestation_results)?;
    info!("Attestation Results:\n {}", results);

    Ok(())
}
