use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use crate::core::verifier::policy::opa;
use crate::fs::*;
use async_trait::async_trait;
use serde_json::{json, Value};

mod policy;

#[derive(Serialize, Deserialize, Debug)]
pub struct Ehd {
    nonce: String,
    public_key: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Tcb {
    is_debuggable: bool,
    cpusvn: u64,
    svn: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Quote {
    is_debuggable: bool,
    cpusvn: u64,
    svn: u64,
    report_data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Policy {
    allow: bool,
    name: String,
    hash: String,
    diagnose: String,
}

#[derive(Debug)]
pub struct Sample {
    workdir: PathBuf,
}

impl Sample {
    pub async fn new(dir: PathBuf) -> Result<Self> {
        let sample = Self { workdir: dir };
        sample.default().await?;
        Ok(sample)
    }
}

#[async_trait]
impl TEETraits for Sample {
    async fn evaluate(&self, evidence: &Evidence) -> Result<AttestationResults> {
        verify(&evidence)
            .await
            .context("Evidence's identity verification error.")?;

        let tcb = tcb_status(&evidence.quote)?;
        let input = json!({
            "cpusvn": tcb.cpusvn,
            "svn": tcb.svn
        })
        .to_string();
        let policy = get(self.opa_policy_path()?.as_path()).await?;
        let reference = get(self.opa_reference_data_path()?.as_path()).await?;
        let evaluation = opa::evaluate(policy, reference, input)?;
        attestation_results(&tcb, evaluation)
    }

    fn opa_policy_path(&self) -> Result<PathBuf> {
        // opa/sample/policy.rego
        Ok(self.workdir.join("opa").join("sample").join("policy.rego"))
    }

    fn opa_reference_data_path(&self) -> Result<PathBuf> {
        // opa/sample/reference
        Ok(self.workdir.join("opa").join("sample").join("reference"))
    }
}

// Demo to fetch the TCB status from the quote
fn tcb_status(quote: &String) -> Result<Tcb> {
    debug!("Quote<sample>:\n{}", &quote);
    let q = serde_json::from_str::<Quote>(quote)
        .context("Deserialize Quote failed.")?;
    Ok(Tcb {
        is_debuggable: false,
        cpusvn: q.cpusvn,
        svn: q.svn,
    })
}

async fn verify(evidence: &Evidence) -> Result<()> {
    // TODO: Emulate the quote identity verificaition.
    let quote = serde_json::from_str::<Quote>(&evidence.quote)
        .context("Deserialize quote failed.")?;
    let ehd = serde_json::from_str::<Ehd>(&evidence.ehd)
        .context("Deserialize ehd failed.")?;
    if quote.report_data != ehd.nonce {
        return Err(anyhow!("Nonce verification failed!"))
    }
    Ok(())
}

fn attestation_results(tcb: &Tcb, evaluation: String) -> Result<AttestationResults> {
    let v: Value = serde_json::from_str(&evaluation)?;

    let policy = Policy {
        allow: v["allow"].as_bool().ok_or(anyhow!("convert allow error"))?,
        name: "policy.rego".to_string(),
        hash: "".to_string(),
        diagnose: evaluation,
    };

    Ok(AttestationResults {
        tee: "sample".to_string(),
        policy: serde_json::to_string(&policy)?,
        tcb: serde_json::to_string(&tcb)?,
    })
}
