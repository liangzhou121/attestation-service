# Tool

Currently, `tool` is a binary package written in Rust. It mainly provides the following functions:
- Set/Get each TEE's Open Policy Engine(OPA) `Policy(.rego)` and `Reference Data(.json)` files. The `Reference Data(.json)` contents should come from such as Reference Value Provider Service(RVPS), but this item is not reflected in this implementation.
- Restore each TEE's `Policy(.rego)` and `Reference Data(.json)` to default value.
- Provide the Attestation Server's `attestation` endpoint testing functionality.

## Supported TEEs

Currently the `tool` supports the following types of TEE:
- sgx
- tdx
- sample: The TEE used to demo/test Attestation Server's functionalities.

## Commands

The `tool` supports each TEE's `Policy(.rego)` and `Reference Data(.json)` configuration and testing subcommands, as the following:
- get-policy
- set-policy
- get-reference-data
- set-reference-data
- restore-default-policy
- restore-default-reference-data
- test-attestation

### get-policy

Get the <TEE> specific evaluation `Policy(.regp)` from Attestation Server."
```SHELL
./tool get-policy --tee <TEE> [--addr <ADDR>]
```
- tee: Specify the target TEE name.
- addr(optional): Designate the attestation server's `management-sock` address. Default is `127.0.0.1:3001`.

### set-policy

Set the <TEE> specific evaluation `Policy(.regp)` according to the content of <POLICY>."
```SHELL
./tool set-policy --tee <TEE> --policy <POLICY> [--addr <ADDR>]
```
- tee: Specify the target TEE name.
- policy: The path of local `Policy(.rego)` which will be upload to Attestation Server.
- addr(optional): Designate the Attestation Server's `management-sock` address. Default is `127.0.0.1:3001`.

### get-reference-data

Get the <TEE> specific `Reference Data(.json)` from Attestation Server.
```SHELL
./tool get-reference-data --tee <TEE> [--addr <ADDR>]
```
- tee: Specify the target TEE name.
- addr(optional): The Attestation Server's `management-sock` address. Default is `127.0.0.1:3001`.

### set-reference-data

Set the <TEE> specific evaluation `Reference Data(.json)` according to the content of <REFERENCE_DATA>.
```SHELL
./tool set-reference-data --tee <TEE> --reference-data <REFERENCE_DATA> [--addr <ADDR>]
```
- tee: Specify the target TEE name.
- reference-data: The path of local `Reference Data(.json)` which will be upload to Attestation Server.
- addr(optional): Designate the Attestation Server's `management-sock` address. Default is `127.0.0.1:3001`.

### restore-default-policy

Restore the Attestation Server's <TEE> specific `Policy(.rego)` to default.
```SHELL
./tool restore-default-policy --tee <TEE> [--addr <ADDR>]
```
- tee: Specify the target TEE name.
- addr(optional): The Attestation Server's `management-sock` address. Default is `127.0.0.1:3001`.

### restore-default-reference-data

Restore the Attestation Server's <TEE> specific `Reference Data(.json)` to default.
```SHELL
./tool restore-default-reference-data --tee <TEE> [--addr <ADDR>]
```
- tee: Specify the target TEE name.
- addr(optional): The Attestation Server's `management-sock` address. Default is `127.0.0.1:3001`.

### test-attestation

Test Attestation Server's `attestation` function with the input <EVIDENCE>.
```SHELL
./tool test-attestation [--evidence <EVIDENCE>] [--addr <ADDR>]
```
- evidence(optional): The evidence which is evaluated by Attestation Server. Default is a imbedded `sample` TEE's evidence.
- addr(optional): The Attestation Server's `attestation-sock` address. Default is `127.0.0.1:3000`.

## Usage

Here are the steps of building and running of this `tool`:

### Build

Build the tool and Attestation Server.
```shell
git clone https://github.com/confidential-containers/attestation-service
cd attestation-service
cargo build --release
```

### Run

- For help information, run:
```shell
./target/release/tool --help
```

- For version information, run:
```shell
./target/release/tool --version
```

- Execute `tool` with a subcommand:
```shell
./target/release/tool <subcommand>
```
