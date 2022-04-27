use std::sync::Arc;
use tonic::{Request, Response, Status};
use attestation_service::Service as ServiceTrait;

use crate::attestation_api::attestation_service_server::AttestationService;
use crate::attestation_api::{AttestationRequest, AttestationResponse};

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
impl AttestationService for Service {
    async fn attestation(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let request: AttestationRequest = request.into_inner();
        let evidence = std::str::from_utf8(&request.evidence).map_err(|e| {
            Status::invalid_argument(format!("parse evidence failed: {}", e.to_string()))
        })?;
        debug!("Evidence:\n{}", evidence);

        let attestation_results = self
            .service
            .attestation(&evidence.to_string())
            .await
            .map_err(|e| {
                Status::invalid_argument(format!("execution failed: {}", e.to_string()))
            })?;

        let res = AttestationResponse {
            attestation_results: attestation_results.into_bytes(),
        };

        Ok(Response::new(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation_api::attestation_service_server::AttestationService;
    use crate::attestation_api::{AttestationRequest, AttestationResponse};
    use serde_json::{json, Value};
    use std::path::Path;
    use std::sync::Arc;
    use tonic::Request;
    use uuid::Uuid;

    fn sample_quote() -> String {
        json!({
            "is_debuggable": false,
            "cpusvn": 1,
            "svn": 1
        })
        .to_string()
    }

    fn sample_evidence() -> String {
        json!({
            "tee": "sample".to_string(),
            "quote": sample_quote(),
            "ehd": "".to_string(),
            "aad": "".to_string()
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_attestation() {
        let user_id = Uuid::new_v4().to_string();

        let attestation_service = Arc::new(
            attestation_service::AttestationService::new(&Path::new("./"), user_id.clone())
                .await
                .unwrap(),
        );
        let service = Service::new(attestation_service.clone());

        let attestaion_request = AttestationRequest {
            evidence: sample_evidence().into_bytes(),
        };
        let request = Request::new(attestaion_request);
        let response = service.attestation(request).await;
        assert!(response.is_ok(), "attestation should success");
        let attestation_response: AttestationResponse = response.unwrap().into_inner();
        let attestation_results = std::str::from_utf8(&attestation_response.attestation_results);
        assert!(
            attestation_results.is_ok(),
            "attestation results should success"
        );
        let v: Value = serde_json::from_str(&attestation_results.unwrap()).unwrap();
        let policy: Value = serde_json::from_str(v["policy"].as_str().unwrap()).unwrap();
        assert!(policy["allow"].as_bool() == Some(true), "allow should true");

        // delete the temporary user files
        std::fs::remove_dir_all(Path::new("./").join(user_id)).unwrap();
    }
}
