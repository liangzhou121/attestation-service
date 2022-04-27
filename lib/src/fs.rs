use anyhow::{anyhow, Result};
use std::path::Path;
use tokio::fs;

pub async fn get(file: &Path) -> Result<String> {
    let contents = fs::read_to_string(file).await?;
    Ok(contents)
}

pub async fn set(file: &Path, content: &str) -> Result<()> {
    let src = file;
    let bak = file.with_extension("bak");

    if src.exists() {
        fs::copy(&src, &bak).await?;
    }

    let res = fs::write(&src, content).await;
    if res.is_err() {
        if bak.exists() {
            // Copy back
            fs::copy(&bak, &src).await?;
        }
        return Err(anyhow!("error: set file failed."));
    }

    fs::remove_file(&bak).await?;
    Ok(())
}
