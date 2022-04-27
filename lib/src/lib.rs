use anyhow::{anyhow, Result};
use async_trait::async_trait;
use management::*;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;

#[macro_use]
extern crate log;

mod core;
mod fs;
pub mod management;

#[derive(Debug)]
pub enum TEEs {
    TDX,
    SGX,
    SEVSNP,
    SAMPLE,
    NONE,
}

#[derive(Debug)]
pub enum PolicyEngine {
    OPA,
    NONE,
}

#[async_trait]
pub trait Service {
    async fn attestation(&self, evidence: &String) -> Result<String>;
}

#[async_trait]
pub trait Management {
    async fn policy_engine_set_file(&self, command: PolicyEngineSetFile) -> Result<()>;
    async fn policy_engine_get_file(&self, command: PolicyEngineGetFile) -> Result<String>;
    fn opa_test(&self, command: OpaTest) -> Result<String>;
}

#[derive(Debug)]
pub struct AttestationService {
    pub locker: RwLock<u8>,
    pub workdir: PathBuf,
    pub attestation: core::Attestation,
}

#[async_trait]
impl Service for AttestationService {
    async fn attestation(&self, evidence: &String) -> Result<String> {
        self.locker.read().await;
        self.attestation.evaluate(evidence).await
    }
}

#[async_trait]
impl Management for AttestationService {
    async fn policy_engine_set_file(&self, command: PolicyEngineSetFile) -> Result<()> {
        self.locker.write().await;
        match command.engine {
            PolicyEngine::OPA => opa::set(self, command).await,
            _ => Err(anyhow!("policy engine is not supported!")),
        }
    }

    async fn policy_engine_get_file(&self, command: PolicyEngineGetFile) -> Result<String> {
        self.locker.read().await;
        match command.engine {
            PolicyEngine::OPA => opa::get(self, command).await,
            _ => Err(anyhow!("policy engine is not supported!")),
        }
    }

    fn opa_test(&self, command: OpaTest) -> Result<String> {
        opa::test(command)
    }
}

impl AttestationService {
    pub async fn new(path: &Path, user_id: String) -> Result<Self> {
        let dir = path.join(user_id);
        Ok(Self {
            locker: RwLock::new(0),
            workdir: dir.clone(),
            attestation: core::Attestation::new(dir.clone()).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Service;
    use crate::Management;
    use serde_json::{json, Value};
    use uuid::Uuid;

    const NONCE: &str = "1234567890";

    fn sample_input(ver: u64) -> String {
        json!({
            "cpusvn": ver,
            "svn": ver
        })
        .to_string()
    }

    fn sample_reference(ver: u64) -> String {
        json!({
            "cpusvn": ver,
            "svn": ver
        })
        .to_string()
    }

    fn sample_quote() -> String {
        json!({
            "is_debuggable": false,
            "cpusvn": 1,
            "svn": 1,
            "report_data": NONCE.to_owned()
        })
        .to_string()
    }

    fn sample_ehd() -> String {
        json!({
            "nonce": NONCE.to_owned(),
            "public_key": "".to_string()
        })
        .to_string()  
    }

    fn sample_evidence() -> String {
        json!({
            "tee": "sample".to_string(),
            "quote": sample_quote(),
            "ehd": sample_ehd(),
            "aad": "".to_string()
        })
        .to_string()
    }

    fn sample_set_file_command(file_type: Files, file_content: String) -> PolicyEngineSetFile {
        PolicyEngineSetFile {
            engine: PolicyEngine::OPA,
            tee: TEEs::SAMPLE,
            file: file_type,
            content: file_content,
        }
    }

    fn sample_get_file_command(file_type: Files) -> PolicyEngineGetFile {
        PolicyEngineGetFile {
            engine: PolicyEngine::OPA,
            tee: TEEs::SAMPLE,
            file: file_type,
        }
    }

    fn sample_policy() -> String {
        let policy = r#"
package policy
        
# By default, deny requests.
default allow = false

allow {
    input.cpusvn >= data.cpusvn
    input.svn >= data.svn
}
"#;
        policy.to_string()
    }

    async fn create_service(user_id: String) -> AttestationService {
        let service = AttestationService::new(&Path::new("./"), user_id.clone()).await;
        assert!(service.is_ok(), "service create should success");
        service.unwrap()
    }

    #[tokio::test]
    async fn test_attestation() {
        let user_id = Uuid::new_v4().to_string();
        let service = create_service(user_id.clone()).await;

        let evidence = sample_evidence();
        let res = service.attestation(&evidence).await;
        assert!(res.is_ok(), "attestation should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        let policy: Value = serde_json::from_str(v["policy"].as_str().unwrap()).unwrap();
        assert!(policy["allow"].as_bool() == Some(true), "allow should true");

        let reference = sample_reference(5);
        let command = sample_set_file_command(Files::Reference, reference);
        let res = service.policy_engine_set_file(command).await;
        assert!(res.is_ok(), "policy engine set file should success");
        let res = service.attestation(&evidence).await;
        assert!(res.is_ok(), "attestation should success");

        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        let policy: Value = serde_json::from_str(v["policy"].as_str().unwrap()).unwrap();
        assert!(
            policy["allow"].as_bool() == Some(false),
            "allow shouldn't true"
        );
        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }

    #[tokio::test]
    async fn test_opa_test() {
        let user_id = Uuid::new_v4().to_string();
        let policy = sample_policy();
        let reference = sample_reference(1);
        let input = sample_input(1);
        let service = create_service(user_id.clone()).await;
        let command = OpaTest {
            policycontent: policy,
            referencecontent: reference,
            inputcontent: input,
        };
        let res = service.opa_test(command);
        assert!(res.is_ok(), "opa test should success");
        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }

    #[tokio::test]
    async fn test_policy_engine_xxx_file() {
        let user_id = Uuid::new_v4().to_string();
        let policy = sample_policy();
        let service = create_service(user_id.clone()).await;
        let command = sample_set_file_command(Files::Reference, policy.clone());
        let res = service.policy_engine_set_file(command).await;
        assert!(res.is_ok(), "policy engine set file should success");
        let command = sample_get_file_command(Files::Reference);
        let value = service.policy_engine_get_file(command).await;
        assert!(value.is_ok(), "policy engine set file should success");
        assert!(value.unwrap() == policy.to_string(), "file should equal");
        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }
}
