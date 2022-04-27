use std::process::exit;

fn real_main() -> Result<(), String> {
    tonic_build::compile_protos("proto/management.proto")
        .map_err(|e| format!("{}", e.to_string()))?;
    tonic_build::compile_protos("proto/attestation.proto")
        .map_err(|e| format!("{}", e.to_string()))?;

    Ok(())
}

fn main() -> shadow_rs::SdResult<()> {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {}", e);
        exit(1);
    }

    shadow_rs::new()
}
