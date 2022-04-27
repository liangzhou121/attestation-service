use super::*;
use anyhow::Result;
use std::path::PathBuf;
use tokio::fs;

impl Sample {
    pub fn opa_path(&self) -> Result<PathBuf> {
        // opa/sample/
        Ok(self.workdir.join("opa").join("sample"))
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
    input.cpusvn >= data.cpusvn
    input.svn >= data.svn
}
"#;
            fs::write(file, policy).await?;
        }

        let file = self.opa_reference_data_path()?;
        if !file.exists() {
            info!("{} isn't exist", file.to_str().unwrap());
            let reference = r#"{
    "cpusvn": 0,
    "svn": 0
}"#;

            fs::write(file, reference).await?;
        }

        Ok(())
    }
}
