use anyhow::Result;
use super::*;
use crate::core::verifier::policy::opa;
use crate::core::verifier::Verifier;
use crate::fs;

pub async fn set(service: &AttestationService, command: PolicyEngineSetFile) -> Result<()> {
    let file = service.attestation.verifiers.opa_files_path(command.file, command.tee)?;
    fs::set(file.as_path(), &command.content).await
}

pub async fn get(service: &AttestationService, command: PolicyEngineGetFile) -> Result<String> {
    let file = service.attestation.verifiers.opa_files_path(command.file, command.tee)?;
    fs::get(file.as_path()).await
}

pub fn test(command: OpaTest) -> Result<String> {
    opa::evaluate(
        command.policycontent,
        command.referencecontent,
        command.inputcontent,
    )
}
