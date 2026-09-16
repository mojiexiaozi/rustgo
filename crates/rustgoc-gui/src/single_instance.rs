//! Per-user GUI instance ownership and coalesced window activation requests.
use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
};

pub struct SingleInstance {
    directory: PathBuf,
    // Never unlink the lock file: all processes must lock the same file object.
    _lock: File,
}

impl SingleInstance {
    pub fn user_directory() -> io::Result<PathBuf> {
        #[cfg(windows)]
        let root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        #[cfg(not(windows))]
        let root = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            });
        root.map(|root| root.join("Rustgo").join("gui-instance"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "无法确定当前用户数据目录"))
    }

    pub fn acquire(directory: &Path) -> io::Result<Option<Self>> {
        Self::acquire_with_contention_hooks(directory, || {}, || {})
    }

    fn acquire_with_contention_hooks(
        directory: &Path,
        on_contention: impl FnOnce(),
        mut on_wait: impl FnMut(),
    ) -> io::Result<Option<Self>> {
        std::fs::create_dir_all(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("instance.lock"))?;
        match lock.try_lock() {
            Ok(()) => {
                let instance = Self {
                    directory: directory.to_owned(),
                    _lock: lock,
                };
                // A new window starts visible, so old requests are unnecessary.
                instance.take_activation()?;
                Ok(Some(instance))
            }
            Err(TryLockError::WouldBlock) => {
                on_contention();
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join("activate"))
                {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                // Wait until the owner acknowledges the request by removing the
                // marker, or take ownership if it exits before doing so.
                loop {
                    match lock.try_lock() {
                        Ok(()) => {
                            let instance = Self {
                                directory: directory.to_owned(),
                                _lock: lock,
                            };
                            instance.take_activation()?;
                            return Ok(Some(instance));
                        }
                        Err(TryLockError::WouldBlock) => {
                            on_wait();
                            if !directory.join("activate").try_exists()? {
                                return Ok(None);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(TryLockError::Error(error)) => return Err(error),
                    }
                }
            }
            Err(TryLockError::Error(error)) => Err(error),
        }
    }

    pub fn take_activation(&self) -> io::Result<bool> {
        match std::fs::remove_file(self.directory.join("activate")) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            Self(std::env::temp_dir().join(format!(
                "rustgo-instance-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn duplicate_requests_activation_and_release_allows_restart() {
        let directory = Directory::new();
        let first = SingleInstance::acquire(&directory.0).unwrap().unwrap();
        assert!(!first.take_activation().unwrap());
        let contender_directory = directory.0.clone();
        let contender =
            std::thread::spawn(move || SingleInstance::acquire(&contender_directory).unwrap());
        wait_for_path(&directory.0.join("activate"));
        assert!(first.take_activation().unwrap());
        assert!(contender.join().unwrap().is_none());
        assert!(!first.take_activation().unwrap());
        drop(first);
        assert!(SingleInstance::acquire(&directory.0).unwrap().is_some());
    }

    #[test]
    fn contender_takes_over_when_owner_exits_before_activation_is_sent() {
        let directory = Directory::new();
        let first = SingleInstance::acquire(&directory.0).unwrap().unwrap();

        let replacement =
            SingleInstance::acquire_with_contention_hooks(&directory.0, || drop(first), || {})
                .unwrap();

        assert!(
            replacement.is_some(),
            "the contender must become the owner when the previous owner exits"
        );
        assert!(
            !replacement.unwrap().take_activation().unwrap(),
            "the takeover must not leave its own stale activation request"
        );
    }

    #[test]
    fn contender_takes_over_when_owner_exits_after_activation_is_sent() {
        let directory = Directory::new();
        let first = std::cell::RefCell::new(Some(
            SingleInstance::acquire(&directory.0).unwrap().unwrap(),
        ));

        let replacement = SingleInstance::acquire_with_contention_hooks(
            &directory.0,
            || {},
            || drop(first.borrow_mut().take()),
        )
        .unwrap();

        assert!(
            replacement.is_some(),
            "the contender must wait and take over if an unresponsive owner exits"
        );
        assert!(!replacement.unwrap().take_activation().unwrap());
    }

    #[test]
    fn child_instance() {
        let Some(directory) = std::env::var_os("RUSTGO_INSTANCE_TEST_DIR") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let _instance = SingleInstance::acquire(&directory).unwrap().unwrap();
        std::fs::write(directory.join("ready"), b"").unwrap();
        loop {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn process_termination_releases_ownership() {
        let directory = Directory::new();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "single_instance::tests::child_instance"])
            .env("RUSTGO_INSTANCE_TEST_DIR", &directory.0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !directory.0.join("ready").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let ready = directory.0.join("ready").exists();
        let contender_directory = directory.0.clone();
        let contender =
            std::thread::spawn(move || SingleInstance::acquire(&contender_directory).unwrap());
        wait_for_path(&directory.0.join("activate"));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(ready, "child did not acquire ownership");
        let restarted = contender.join().unwrap().unwrap();
        assert!(
            !restarted.take_activation().unwrap(),
            "discard stale activation after a crash"
        );
    }

    fn wait_for_path(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(path.exists(), "{} was not created", path.display());
    }
}
