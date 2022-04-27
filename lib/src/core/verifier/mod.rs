use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use crate::*;
use crate::core::*;

pub mod policy;
mod sample;
mod sgx;
mod tdx;

#[async_trait]
pub trait Verifier {
    async fn evaluate(&self, evidence: &Evidence) -> Result<AttestationResults>;
    fn opa_files_path(&self, file: Files, tee: TEEs) -> Result<PathBuf>;
}

#[async_trait]
pub trait TEETraits {
    async fn evaluate(&self, evidence: &Evidence) -> Result<AttestationResults>;
    fn opa_policy_path(&self) -> Result<PathBuf>;
    fn opa_reference_data_path(&self) -> Result<PathBuf>;
}

#[derive(Debug)]
pub struct Verifiers {
    pub tdx: tdx::Tdx,
    pub sgx: sgx::Sgx,
    pub sample: sample::Sample,
}

impl Verifiers {
    pub async fn new(workdir: PathBuf) -> Result<Self> {
        Ok(Self {
            tdx: tdx::Tdx::new(workdir.clone()).await?,
            sgx: sgx::Sgx::new(workdir.clone()).await?,
            sample: sample::Sample::new(workdir.clone()).await?,
        })
    }
}

#[async_trait]
impl Verifier for Verifiers {
    async fn evaluate(&self, evidence: &Evidence) -> Result<AttestationResults> {
        match evidence.tee.as_str() {
            "sample" => Ok(self.sample.evaluate(evidence).await?),
            "sgx" => Ok(self.sgx.evaluate(evidence).await?),
            "tdx" => Ok(self.tdx.evaluate(evidence).await?),
            _ => Err(anyhow!("not supported!")),
        }
    }

    fn opa_files_path(&self, file: Files, tee: TEEs) -> Result<PathBuf> {
        let tee = match tee {
            TEEs::SGX => Ok(&self.sgx as &dyn TEETraits),
            TEEs::TDX => Ok(&self.tdx as &dyn TEETraits),
            TEEs::SAMPLE => Ok(&self.sample as &dyn TEETraits),
            _ => Err(anyhow!("tee not supported!")),
        }?;
        match file {
            Files::Policy => tee.opa_policy_path(),
            Files::Reference => tee.opa_reference_data_path(),
            _ => Err(anyhow!("file not supported!")),
        }
    }
}
