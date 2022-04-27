# Attestation Server

Attestation Server is a user space service for attestation procedure. 
It receives and verifies the TEE's [Evidence](https://github.com/confidential-containers/attestation-service/issues/1) and response the corresponding [Attestation Results](https://github.com/confidential-containers/attestation-service/issues/1) to ensure the Evidence's generation environment is a real TEE environment and it's TCB status are as expected.


Consumers of Attestation Server include: 

- [kbs](https://github.com/confidential-containers/kbs)

## Usage

Here are the steps of building and running Attestation Server:

### Build

Build Attestation Server and its configuration tool.

```shell
git clone https://github.com/confidential-containers/attestation-service
cd attestation-service
cargo build
```

### Run

For help information, just run:

```shell
./attestation-server --help
```

Start Attestation Server and specify the listen port of its gRPC service:

```shell
./attestation-server --listen 127.0.0.1:1234
```

If you want to see the runtime log:
```shell
RUST_LOG=debug ./attestation-server --listen 127.0.0.1:1234
```
