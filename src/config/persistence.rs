//! Atomic configuration persistence with the Go implementation's backup
//! semantics.

use super::Config;
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn save_atomic(path: &str, cfg: &Config) -> Result<()> {
    let mut cfg = cfg.clone();
    cfg.password_for_save();
    let mut data = serde_json::to_vec_pretty(&cfg).context("encode config")?;
    data.push(b'\n');

    let target = Path::new(path);
    let directory = target.parent().unwrap_or_else(|| Path::new("."));
    let temp = directory.join(format!(".config-{}.tmp", random_suffix()));
    write_synced(&temp, &data)?;

    if let Ok(metadata) = fs::metadata(target) {
        let permissions = metadata.permissions();
        let _ = fs::set_permissions(&temp, permissions);
    }

    let backup = PathBuf::from(format!("{path}.bak"));
    if target.exists() {
        if let Err(error) = copy_synced(target, &backup) {
            let _ = fs::remove_file(&temp);
            return Err(error).context("backup config");
        }
    }

    #[cfg(windows)]
    {
        if target.exists() {
            let staged = directory.join(format!(".config-old-{}.tmp", random_suffix()));
            fs::rename(target, &staged).context("stage current config")?;
            if let Err(error) = fs::rename(&temp, target) {
                let _ = fs::rename(&staged, target);
                let _ = fs::remove_file(&temp);
                return Err(anyhow!("replace config: {error}"));
            }
            let _ = fs::remove_file(staged);
            return Ok(());
        }
    }

    if let Err(error) = fs::rename(&temp, target) {
        let _ = fs::remove_file(&temp);
        return Err(anyhow!("replace config: {error}"));
    }
    Ok(())
}

fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path).context("create temporary config")?;
    file.write_all(data).context("write temporary config")?;
    file.sync_all().context("sync temporary config")?;
    Ok(())
}

fn copy_synced(source: &Path, target: &Path) -> Result<()> {
    let data = fs::read(source).context("read config for backup")?;
    write_synced(target, &data)
}

fn random_suffix() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen()
}
