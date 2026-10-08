pub mod limits;

pub const IFB_DEVICE: &str = "wings-dl";
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{HELPER_ARG, helper_main};

use anyhow::{Context, ensure};
use limits::BandwidthLimits;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Weak},
};

static LOCKS: LazyLock<parking_lot::Mutex<HashMap<uuid::Uuid, Weak<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Default::default);

pub fn lock(server: uuid::Uuid) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = LOCKS.lock();
    if let Some(lock) = locks.get(&server).and_then(Weak::upgrade) {
        return lock;
    }

    locks.retain(|_, lock| lock.strong_count() > 0);
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(server, Arc::downgrade(&lock));

    lock
}

const BYPASS_CAPABILITIES: [(u32, &str); 3] =
    [(12, "NET_ADMIN"), (13, "NET_RAW"), (21, "SYS_ADMIN")];

fn validate_capabilities(status: &str) -> Result<(), anyhow::Error> {
    let bounding = status
        .lines()
        .find_map(|line| line.strip_prefix("CapBnd:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .context("failed to read container capabilities")?;

    for (bit, name) in BYPASS_CAPABILITIES {
        ensure!(
            bounding & (1 << bit) == 0,
            "bandwidth limits require a container without {name}"
        );
    }

    Ok(())
}

#[async_trait::async_trait]
pub trait BandwidthBackend: Send + Sync {
    async fn ready(&self) -> Result<(), anyhow::Error>;

    async fn apply(&self, pid: u32, limits: BandwidthLimits) -> Result<(), anyhow::Error>;
}

#[cfg(not(target_os = "linux"))]
struct UnsupportedBandwidth;

#[cfg(not(target_os = "linux"))]
#[async_trait::async_trait]
impl BandwidthBackend for UnsupportedBandwidth {
    async fn ready(&self) -> Result<(), anyhow::Error> {
        anyhow::bail!("bandwidth limits are only supported on linux")
    }

    async fn apply(&self, _pid: u32, limits: BandwidthLimits) -> Result<(), anyhow::Error> {
        ensure!(
            !limits.is_limited(),
            "bandwidth limits are only supported on linux"
        );

        Ok(())
    }
}

pub fn backend() -> &'static dyn BandwidthBackend {
    #[cfg(target_os = "linux")]
    return &linux::NetlinkBandwidth;

    #[cfg(not(target_os = "linux"))]
    return &UnsupportedBandwidth;
}

pub async fn apply(
    docker: &bollard::Docker,
    container_id: &str,
    limits: BandwidthLimits,
) -> Result<(), anyhow::Error> {
    let container = docker
        .inspect_container(container_id, None)
        .await
        .with_context(|| format!("failed to inspect container {container_id}"))?;

    let Some(pid) = container
        .state
        .filter(|state| state.running == Some(true))
        .and_then(|state| state.pid)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
    else {
        return Ok(());
    };

    let host_config = container.host_config.unwrap_or_default();
    let network_mode = host_config.network_mode.as_deref().unwrap_or_default();
    if matches!(network_mode, "host" | "none") || network_mode.starts_with("container:") {
        ensure!(
            !limits.is_limited(),
            "bandwidth limits require a bridge network"
        );

        return Ok(());
    }

    if limits.is_limited() {
        let status = tokio::fs::read_to_string(format!("/proc/{pid}/status"))
            .await
            .with_context(|| format!("failed to read capabilities of pid {pid}"))?;
        validate_capabilities(&status)?;
    }

    backend().apply(pid, limits).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(bounding: &str) -> String {
        format!("Name:\tjava\nCapEff:\t0000000000000000\nCapBnd:\t{bounding}\n")
    }

    #[test]
    fn capabilities_that_bypass_shaping_are_rejected() {
        assert!(validate_capabilities(&status("00000000000000e1")).is_ok());
        assert!(validate_capabilities(&status("00000000000004e1")).is_ok());
        assert!(validate_capabilities(&status("00000000000020e1")).is_err());
        assert!(validate_capabilities(&status("00000000000010e1")).is_err());
        assert!(validate_capabilities(&status("00000000002000e1")).is_err());
        assert!(validate_capabilities(&status("000001ffffffffff")).is_err());
        assert!(validate_capabilities("Name:\tjava\n").is_err());
    }

    #[tokio::test]
    async fn lock_is_shared_per_server_and_released() {
        let server = uuid::Uuid::new_v4();
        let first = lock(server);
        assert!(Arc::ptr_eq(&first, &lock(server)));
        assert!(!Arc::ptr_eq(&first, &lock(uuid::Uuid::new_v4())));

        let _guard = first.lock().await;
        assert!(lock(server).try_lock().is_err());
    }
}
