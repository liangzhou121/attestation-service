# Tool

Currently, `tool` is a binary package written in Rust. It mainly provides the following functions:
- Set/get different TEE's corresponding Open Policy Engine(OPA) _Policy_ and _Reference_ files. The reference values should come from such as reproduce build, but this item is not reflected in this implementation.
- Provide OPA _Policy_ and _Reference_ files' testing functionality.
- Test the `sample` TEE's `attestation` functionality.

## Supported TEEs

Currently the `tool` supports the following TEEs:
- sgx
- tdx
- sample: The TEE used to implement and demo internel functions.

## Usage

You can use `cargo build` to compile this project and place the generated executable file in the `/bin` directory.

The basic usage is as follows.

```bash
tool [OPTIONS]

# Specify the mangement address, remember to add double quotes to the address.
# The default address is "127.0.0.1:1234".
--management-api <ADDRESS> 

# Set the <TEE> corresponding OPA's Policy file, according to the contents in <POLICY_PATH>.
--set-opa-policy <TEE> <POLICY_PATH> [--management-api <ADDRESS>]

# Get the contents of the <TEE> corresponding Policy file.
# The download file will be stored in the current working directory.
--get-opa-policy <TEE> [--management-api <ADDRESS>]

# Set the <TEE> corresponding OPA's Reference file, according to the contents in <REFERENCE_PATH>.
--set-opa-reference <TEE> <REFERENCE_PATH> [--management-api <ADDRESS>]

# Get the contents of the <TEE> corresponding Reference file.
# The download file will be stored in the current working directory.
--get-opa-reference <TEE> [--management-api <ADDRESS>]

# Test the local Policy, local Reference with the local Input.
# POLICY_PATH: the tested Policy file's path.
# REFERENCE_PATH: the tested Reference file's path.
# INPUT_PATH: the Input file's path
--test-opa <POLICY_PATH> <REFERENCE_PATH> <INPUT_PATH> [--management-api <ADDRESS>]

# This option will generate a <TEE> recognizable Evidence and invoke the Attestation to verify it.
# Currently, it only support the "sample" TEE.
--test-attestation <TEE> [--management-api <ADDRESS>]

# Prints help information.
--help

# Prints version information.
--version
```
