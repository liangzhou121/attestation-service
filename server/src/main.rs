use anyhow::Result;
use attestation_api::attestation_service_server::AttestationServiceServer;
use attestation_service;
use clap::{App, Arg};
use management_api::opa_service_server::OpaServiceServer;
use shadow_rs::shadow;
use std::path::Path;
use std::sync::Arc;
use tokio;
use tonic::transport::Server;
pub mod management_api {
    tonic::include_proto!("management");
}
pub mod attestation_api {
    tonic::include_proto!("attestation");
}

#[macro_use]
extern crate log;
shadow!(build);

mod attestation;
mod management;

pub async fn server(addr: &str) -> Result<()> {
    let service = Arc::new(
        attestation_service::AttestationService::new(
            &Path::new("/opt/attestation-service"),
            "".to_string(),
        )
        .await?,
    );

    let addr = addr.parse()?;
    let opa_service = management::opa::Service::new(service.clone());
    let attestation_service = attestation::Service::new(service.clone());

    Server::builder()
        .add_service(OpaServiceServer::new(opa_service))
        .add_service(AttestationServiceServer::new(attestation_service))
        .serve(addr)
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    let matches = App::new("attestation-server")
        .version(version.as_str())
        .long_version(version.as_str())
        .author("Confidential-Containers Team")
        .arg(
            Arg::with_name("listen")
                .short("l")
                .long("listen")
                .value_name("sockaddr")
                .help("Work in listen mode")
                .takes_value(true),
        )
        .get_matches();

    let sockaddr = match matches.is_present("listen") {
        true => matches.value_of("listen").unwrap().to_string(),
        false => "127.0.0.1:1234".to_string(),
    };

    debug!("Server listen addr: {}", &sockaddr);
    let server = server(&sockaddr);
    match server.await {
        Ok(_) => debug!("Success"),
        Err(e) => error!("Launch service failed with: {}", e.to_string()),
    }
}
