use anyhow::{Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use crate::*;

mod proxy;
pub mod verifier;
use verifier::Verifier;

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub tee: String,
    pub quote: String,
    pub ehd: String,
    pub aad: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResults {
    pub tee: String,
    pub policy: String,
    pub tcb: String,
}

#[derive(Debug)]
pub struct Attestation {
    pub verifiers: verifier::Verifiers,
    pub proxies: proxy::Proxies,
}

impl Attestation {
    pub async fn new(workdir: PathBuf) -> Result<Self> {
        Ok(Self {
            verifiers: verifier::Verifiers::new(workdir).await?,
            proxies: proxy::Proxies::new(),
        })
    }

    pub async fn evaluate(&self, evidence: &String) -> Result<String> {
        let ev = 
            serde_json::from_str::<Evidence>(evidence).context("Deserialize Evidence failed.")?;
        let results = 
            self.verifiers
            .evaluate(&ev)
            .await?;
        // Fixme: enable the self.proxies.attestation(&evidence)
        let results = serde_json::to_string(&results)?;
        debug!("Attestation Results:\n{}", &results);
        Ok(results)
    }
}
