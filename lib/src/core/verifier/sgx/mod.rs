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
    mrenclave: String,
    mrsigner: String,
    product_id: u64,
    cpusvn: u64,
    svn: u64,
}

#[derive(Debug)]
pub struct Sgx {
    workdir: PathBuf,
}

impl Sgx {
    pub async fn new(dir: PathBuf) -> Result<Self> {
        let sgx = Self { workdir: dir };
        sgx.default().await?;
        Ok(sgx)
    }
}

#[async_trait]
impl TEETraits for Sgx {
    async fn evaluate(&self, _evidence: &Evidence) -> Result<AttestationResults> {
        Err(anyhow!("not implemented!"))
    }
    fn opa_policy_path(&self) -> Result<PathBuf> {
        // opa/sgx/policy.rego
        Ok(self.workdir.join("opa").join("sgx").join("policy.rego"))
    }

    fn opa_reference_data_path(&self) -> Result<PathBuf> {
        // opa/sgx/reference
        Ok(self.workdir.join("opa").join("sgx").join("reference"))
    }
}
