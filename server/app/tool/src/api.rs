use crate::management_api::files::*;
use clap::{App, Arg};
use shadow_rs::shadow;
use std::fs;
use std::io::prelude::*;
use std::path::Path;

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
mod opa;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter(None, log::LevelFilter::Info)
        .init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    let matches = App::new("client")
    .version(version.as_str())
    .long_version(version.as_str())
    .author("Confidential-Containers Team")
    .arg(
        Arg::with_name("management_api")
            .long("management-api")
            .value_name("MANAGEMENT_API_ADDRESS")
            .help("Specify the Attestation Service Management API's connection address.")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("set_opa_policy")
            .long("set-opa-policy")
            .value_name("TEE")
            .value_name("POLICY_PATH")
            .help("Set the <TEE> used OPA policy file, according to the contents in <POLICY_PATH>.")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("set_opa_reference")
            .long("set-opa-reference")
            .value_name("TEE")
            .value_name("REFERENCE_PATH")
            .help("Generate the <TEE> used OPA reference file, according to the contents in <REFERENCE_PATH>.")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("get_opa_policy")
            .long("get-opa-policy")
            .value_name("TEE")
            .help("Get the contents of the <TEE>'s policy file.")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("get_opa_reference")
            .long("get-opa-reference")
            .value_name("TEE")
            .help("Get the contents of the <TEE>'s reference file.")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("test_opa")
            .long("test-opa")
            .value_name("POLICY_PATH")
            .value_name("REFERENCE_PATH")
            .value_name("INPUT_PATH")
            .help("Test the contents of <POLICY_PATH>, <REFERENCE_PATH>, and <INPUT_PATH> with OPA engine")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("test_attestation")
            .long("test-attestation")
            .value_name("TEE")
            .help("Get the <TEE>'s attestation, currently only supports the Sample TEE.")
            .takes_value(true),
    )
    .get_matches();

    let management_api = if matches.is_present("management_api") {
        matches.value_of("management_api").unwrap().to_string()
    } else {
        "127.0.0.1:1234".to_string()
    };
    info!("Connect to Attestation Service: {}", management_api);

    if matches.is_present("set_opa_policy") {
        let _res = opa::config_opa_cmd(
            matches.values_of("set_opa_policy").unwrap().collect(),
            Names::Policy,
            &management_api,
        )
        .await
        .map_err(|e| {
            info!("failed: {}", e.to_string());
        });
    }

    if matches.is_present("set_opa_reference") {
        let _res = opa::config_opa_cmd(
            matches.values_of("set_opa_reference").unwrap().collect(),
            Names::Reference,
            &management_api,
        )
        .await
        .map_err(|e| {
            info!("failed: {}", e.to_string());
        });
    }

    if matches.is_present("get_opa_policy") {
        let mut path = "./".to_string();
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        let tee = matches.value_of("get_opa_policy").unwrap();
        let content = opa::query_opa_cmd(tee, Names::Policy, &management_api)
            .await
            .map_err(|e| {
                info!("failed: {}", e.to_string());
            })
            .unwrap();

        let file = Path::new(&path).join(tee.to_owned() + "_policy.rego");
        let _res = fs::File::create(file)
            .expect("Failed to create the file.")
            .write_all(content.as_bytes())
            .expect("Faied to write the policy content into the file.");
    }

    if matches.is_present("get_opa_reference") {
        let mut path = "./".to_string();
        if !path.ends_with("/") {
            path = format!("{}/", path);
        }
        let tee = matches.value_of("get_opa_reference").unwrap();
        let content = opa::query_opa_cmd(tee, Names::Reference, &management_api)
            .await
            .map_err(|e| {
                info!("failed: {}", e.to_string());
            })
            .unwrap();

        let file = Path::new(&path).join(tee.to_owned() + "_reference");
        let _res = fs::File::create(file)
            .expect("Failed to create the file.")
            .write_all(content.as_bytes())
            .expect("Faied to write the policy content into the file.");
    }

    if matches.is_present("test_opa") {
        let args = matches.values_of("test_opa").unwrap().collect();
        let _res = opa::test_opa(args, &management_api).await.map_err(|e| {
            info!("failed: {}", e.to_string());
        });
    }

    if matches.is_present("test_attestation") {
        let _res = attestation::attestation_cmd(
            matches.value_of("test_attestation").unwrap(),
            &management_api,
        )
        .await
        .map_err(|e| {
            info!("failed: {}", e.to_string());
        });
    }
}
