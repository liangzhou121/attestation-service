use std::sync::Arc;
use tonic::{Request, Response, Status};
extern crate attestation_service;
use attestation_service::TEEs;
use attestation_service::PolicyEngine;
use attestation_service::management;
use attestation_service::Management as ManagementTrait;

use super::super::management_api::Files;
use crate::management_api::opa_service_server::OpaService;
use crate::management_api::{ConfigOpaRequest, ConfigOpaResponse};
use crate::management_api::{QueryOpaRequest, QueryOpaResponse};
use crate::management_api::{TestOpaRequest, TestOpaResponse};

#[derive(Debug)]
pub struct Service {
    service: Arc<attestation_service::AttestationService>,
}

impl Service {
    pub fn new(instance: Arc<attestation_service::AttestationService>) -> Self {
        Self { service: instance }
    }
}

#[tonic::async_trait]
impl OpaService for Service {
    async fn config_opa(
        &self,
        request: Request<ConfigOpaRequest>,
    ) -> Result<Response<ConfigOpaResponse>, Status> {
        let request: ConfigOpaRequest = request.into_inner();
        let file = parse(request.file)?;
        let content = std::str::from_utf8(&request.content).map_err(|e| {
            Status::invalid_argument(format!("parse content failed: {}", e.to_string()))
        })?;
        debug!("Content:\n{}", content);
        let command = management::PolicyEngineSetFile {
            engine: PolicyEngine::OPA,
            tee: file.0,
            file: file.1,
            content: content.to_string(),
        };
        self.service
            .policy_engine_set_file(command)
            .await
            .map_err(|e| {
                Status::invalid_argument(format!("execution failed: {}", e.to_string()))
            })?;

        let res = ConfigOpaResponse {
            status: "OK".to_string().into_bytes(),
        };

        Ok(Response::new(res))
    }

    async fn query_opa(
        &self,
        request: Request<QueryOpaRequest>,
    ) -> Result<Response<QueryOpaResponse>, Status> {
        let request: QueryOpaRequest = request.into_inner();
        let file = parse(request.file)?;
        let command = management::PolicyEngineGetFile {
            engine: PolicyEngine::OPA,
            tee: file.0,
            file: file.1,
        };
        let content = self
            .service
            .policy_engine_get_file(command)
            .await
            .map_err(|e| {
                Status::invalid_argument(format!("execution failed: {}", e.to_string()))
            })?;
        debug!("Content:\n{}", content);
        let res = QueryOpaResponse {
            content: content.into_bytes(),
        };

        Ok(Response::new(res))
    }

    async fn test_opa(
        &self,
        request: Request<TestOpaRequest>,
    ) -> Result<Response<TestOpaResponse>, Status> {
        let request: TestOpaRequest = request.into_inner();
        let policy = std::str::from_utf8(&request.policy).map_err(|e| {
            Status::invalid_argument(format!("parse policy failed: {}", e.to_string()))
        })?;
        let reference = std::str::from_utf8(&request.reference).map_err(|e| {
            Status::invalid_argument(format!("parse reference failed: {}", e.to_string()))
        })?;
        let input = std::str::from_utf8(&request.input).map_err(|e| {
            Status::invalid_argument(format!("parse input failed: {}", e.to_string()))
        })?;
        let command = management::OpaTest {
            policycontent: policy.to_string(),
            referencecontent: reference.to_string(),
            inputcontent: input.to_string(),
        };
        let results = self.service.opa_test(command).map_err(|e| {
            Status::invalid_argument(format!("execution failed: {}", e.to_string()))
        })?;

        let res = TestOpaResponse {
            status: results.into_bytes(),
        };

        Ok(Response::new(res))
    }
}

fn parse(file: Option<Files>) -> Result<(TEEs, management::Files), Status> {
    let file = match file {
        Some(file) => Ok(file),
        _ => Err(Status::invalid_argument("file is error")),
    }?;
    let tee = match file.tee {
        0 => Ok(TEEs::SGX),
        1 => Ok(TEEs::TDX),
        2 => Ok(TEEs::SEVSNP),
        3 => Ok(TEEs::SAMPLE),
        _ => Err(Status::invalid_argument("The TEE isn't supported")),
    }?;
    let name = match file.name {
        0 => Ok(management::Files::Policy),
        1 => Ok(management::Files::Reference),
        _ => Err(Status::invalid_argument("The File isn't supported")),
    }?;
    Ok((tee, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management_api::files::*;
    use crate::management_api::opa_service_server::OpaService;
    use crate::management_api::ConfigOpaRequest;
    use crate::management_api::Files;
    use crate::management_api::QueryOpaRequest;
    use crate::management_api::TestOpaRequest;
    use serde_json::json;
    use std::path::Path;
    use std::sync::Arc;
    use uuid::Uuid;

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

    fn sample_policy_files() -> Files {
        Files {
            tee: Tees::Sample as i32,
            name: Names::Policy as i32,
        }
    }

    async fn create_service(user_id: String) -> Service {
        let attestation_service = Arc::new(
            attestation_service::AttestationService::new(&Path::new("./"), user_id)
                .await
                .unwrap(),
        );
        Service::new(attestation_service.clone())
    }

    #[tokio::test]
    async fn test_config_opa() {
        let user_id = Uuid::new_v4().to_string();
        let service = create_service(user_id.clone()).await;

        let config_opa_request = ConfigOpaRequest {
            file: Some(sample_policy_files()),
            content: sample_policy().into_bytes(),
        };
        let request = Request::new(config_opa_request);
        let response = service.config_opa(request).await;
        assert!(response.is_ok(), "config opa should success");

        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }

    #[tokio::test]
    async fn test_query_opa() {
        let user_id = Uuid::new_v4().to_string();
        let service = create_service(user_id.clone()).await;

        let config_opa_request = QueryOpaRequest {
            file: Some(sample_policy_files()),
        };
        let request = Request::new(config_opa_request);
        let response = service.query_opa(request).await;
        assert!(response.is_ok(), "config opa should success");

        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }

    #[tokio::test]
    async fn test_test_opa() {
        let user_id = Uuid::new_v4().to_string();
        let service = create_service(user_id.clone()).await;

        let config_opa_request = TestOpaRequest {
            policy: sample_policy().into_bytes(),
            reference: sample_reference(1).into_bytes(),
            input: sample_input(1).into_bytes(),
        };
        let request = Request::new(config_opa_request);
        let response = service.test_opa(request).await;
        assert!(response.is_ok(), "test opa should success");

        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }
}
