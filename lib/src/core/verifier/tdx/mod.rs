use anyhow::{anyhow, Result};
use std::path::PathBuf;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;

mod policy;

#[derive(Serialize, Deserialize, Debug)]
pub struct Policy {
    allow: bool,
    name: String,
    hash: String,
    diagnose: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Collateral {
    qeidcertshash: String,
    qeidcrlhash: String,
    qeidhash: String,
    quotehash: String,
    tcbinfocertshash: String,
    tcbinfocrlhash: String,
    tcbinfohash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ehd {
    nonce: String,
    public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tcb {
    collateral: Collateral,
    ehd: Ehd,
    is_debuggable: bool,
    mrseam: String,
    mrseamsigner: String,
    mrtd: String,
    rtmr0: String,
    rtmr1: String,
    rtmr2: String,
    rtmr3: String,
    cpusvn: u64,
    svn: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tdel {
    info: String,
    data: String,
}

#[derive(Debug)]
pub struct Tdx {
    workdir: PathBuf,
}

impl Tdx {
    pub async fn new(dir: PathBuf) -> Result<Self> {
        let tdx = Self { workdir: dir };
        tdx.default().await?;
        Ok(tdx)
    }
}

#[async_trait]
impl TEETraits for Tdx {
    async fn evaluate(&self, _evidence: &Evidence) -> Result<AttestationResults> {
        Err(anyhow!("not implemented!"))
    }
    fn opa_policy_path(&self) -> Result<PathBuf> {
        // opa/tdx/policy.rego
        Ok(self.workdir.join("opa").join("tdx").join("policy.rego"))
    }

    fn opa_reference_data_path(&self) -> Result<PathBuf> {
        // opa/tdx/reference
        Ok(self.workdir.join("opa").join("tdx").join("reference"))
    }
}
