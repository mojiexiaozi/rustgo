#![forbid(unsafe_code)]
#![allow(dead_code)]

#[cfg(windows)]
pub mod platform {
    pub struct TrayIcon;

    impl TrayIcon {
        pub fn new() -> anyhow::Result<Self> {
            Ok(Self)
        }
    }
}

#[cfg(not(windows))]
pub mod platform {
    pub struct TrayIcon;

    impl TrayIcon {
        pub fn new() -> anyhow::Result<Self> {
            Ok(Self)
        }
    }
}
