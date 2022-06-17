use anyhow::Result;
use clap::{App, Arg, SubCommand};
use shadow_rs::shadow;

mod attestation;
mod management;

pub mod management_api {
    tonic::include_proto!("management");
}
pub mod attestation_api {
    tonic::include_proto!("attestation");
}
pub mod common {
    tonic::include_proto!("common");
}

#[macro_use]
extern crate log;
shadow!(build);

#[tokio::main]
async fn main() -> Result<()> {
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
    .subcommand(SubCommand::with_name("set-policy")
        .about("Set the <TEE> specific evaluation `Policy(.regp)` according to the content of <POLICY>.")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `management-sock` address.'"))
        .arg(Arg::from_usage("--tee=[TEE] 'The target TEE name'"))
        .arg(Arg::from_usage("--policy=[POLICY] 'Policy path'"))
    )
    .subcommand(SubCommand::with_name("set-reference-data")
        .about("Set the <TEE> specific evaluation `Reference Data(.json)` according to the content of <REFERENCE_DATA>.")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `management-sock` address.'"))
        .arg(Arg::from_usage("--tee=[TEE] 'The target TEE name'"))
        .arg(Arg::from_usage("--reference-data=[REFERENCE_DATA] 'Reference Data path'"))
    )
    .subcommand(SubCommand::with_name("get-policy")
        .about("Get the <TEE> specific evaluation `Policy(.regp)` from Attestation Server.")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `management-sock` address.'"))
        .arg(Arg::from_usage("--tee=[TEE] 'The target TEE name'"))
    )
    .subcommand(SubCommand::with_name("get-reference-data")
        .about("Get the <TEE> specific `Reference Data(.json)` from Attestation Server.")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `management-sock` address.'"))
        .arg(Arg::from_usage("--tee=[TEE] 'The target TEE name'"))
    )
    .subcommand(SubCommand::with_name("restore-default-policy")
        .about("Restore the Attestation Server's <TEE> specific `Policy(.rego)` to default.")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `management-sock` address.'"))
        .arg(Arg::from_usage("--tee=[TEE] 'The target TEE name'"))
    )
    .subcommand(SubCommand::with_name("restore-default-reference-data")
        .about("Restore the Attestation Server's <TEE> specific `Reference Data(.json)` to default.")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `management-sock` address.'"))
        .arg(Arg::from_usage("--tee=[TEE] 'The target TEE name'"))
    )
    .subcommand(SubCommand::with_name("test-attestation")
        .about("Test Attestation Server's `attestation` function with the input <EVIDENCE>")
        .arg(Arg::from_usage("--addr=[ADDR] 'Attestation Service's `attestation-sock` address.'"))
        .arg(Arg::from_usage("--evidence=[EVIDENCE] 'The evidence which is evaluated by Attestation Server. Default is a imbedded `sample` TEE's evidence'"))
    )
    .get_matches();

    if let Some(matches) = matches.subcommand_matches("get-policy") {
        management::get_policy_cmd(matches.value_of("tee"), matches.value_of("addr")).await?;
    }

    if let Some(matches) = matches.subcommand_matches("get-reference-data") {
        management::get_reference_data_cmd(matches.value_of("tee"), matches.value_of("addr"))
            .await?;
    }

    if let Some(matches) = matches.subcommand_matches("set-policy") {
        management::set_policy_cmd(
            matches.value_of("tee"),
            matches.value_of("policy"),
            matches.value_of("addr"),
        )
        .await?;
    }

    if let Some(matches) = matches.subcommand_matches("set-reference-data") {
        management::set_reference_data_cmd(
            matches.value_of("tee"),
            matches.value_of("reference-data"),
            matches.value_of("addr"),
        )
        .await?;
    }

    if let Some(matches) = matches.subcommand_matches("restore-default-policy") {
        management::restore_default_policy_cmd(matches.value_of("tee"), matches.value_of("addr"))
            .await?;
    }

    if let Some(matches) = matches.subcommand_matches("restore-default-reference-data") {
        management::restore_default_reference_data_cmd(
            matches.value_of("tee"),
            matches.value_of("addr"),
        )
        .await?;
    }

    if let Some(matches) = matches.subcommand_matches("test-attestation") {
        attestation::attestation_cmd(matches.value_of("evidence"), matches.value_of("addr"))
            .await?;
    }

    Ok(())
}
