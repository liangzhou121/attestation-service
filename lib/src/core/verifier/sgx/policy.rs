use super::*;
use anyhow::Result;
use std::path::PathBuf;
use tokio::fs;

impl Sgx {
    pub fn opa_path(&self) -> Result<PathBuf> {
        // opa/sgx/
        Ok(self.workdir.join("opa").join("sgx"))
    }

    //Set default policy and reference file.
    pub async fn default(&self) -> Result<()> {
        let path = self.opa_path()?;
        if !path.exists() {
            fs::create_dir_all(path).await?;
        }

        let file = self.opa_policy_path()?;
        if !file.exists() {
            info!("{} isn't exist", file.to_str().unwrap());
            let policy = r#"
package policy

# By default, deny requests.
default allow = false

allow {
    mrEnclave_is_grant
    mrSigner_is_grant
    input.productId >= data.productId
    input.svn >= data.svn
}

mrEnclave_is_grant {
    count(data.mrEnclave) == 0
}
mrEnclave_is_grant {
    count(data.mrEnclave) > 0
    input.mrEnclave == data.mrEnclave[_]
}

mrSigner_is_grant {
    count(data.mrSigner) == 0
}
mrSigner_is_grant {
    count(data.mrSigner) > 0
    input.mrSigner == data.mrSigner[_]
}
"#;
            fs::write(file, policy).await?;
        }

        let file = self.opa_reference_data_path()?;
        if !file.exists() {
            info!("{} isn't exist", file.to_str().unwrap());
            let reference = r#"{
    "mrEnclave": [],
    "mrSigner": [],
    "productId": 0,
    "svn": 0
}"#;

            fs::write(file, reference).await?;
        }

        Ok(())
    }
}
