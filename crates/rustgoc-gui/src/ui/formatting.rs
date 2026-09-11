#![forbid(unsafe_code)]

/// Format bytes using binary units (KiB, MiB, GiB, TiB) to match web client
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    let (amount, unit) = if bytes >= TIB {
        (bytes as f64 / TIB as f64, "TiB")
    } else if bytes >= GIB {
        (bytes as f64 / GIB as f64, "GiB")
    } else if bytes >= MIB {
        (bytes as f64 / MIB as f64, "MiB")
    } else if bytes >= KIB {
        (bytes as f64 / KIB as f64, "KiB")
    } else {
        return format!("{} B", bytes);
    };

    // Use 1 decimal place if amount < 10, otherwise use integer
    if amount >= 10.0 {
        format!("{:.0} {}", amount, unit)
    } else {
        format!("{:.1} {}", amount, unit)
    }
}

/// Format bytes per second rate (matches web client formatRate)
pub fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

/// Format basis points as percentage (matches web client formatPercent)
pub fn format_percent(basis_points: u64) -> String {
    format!("{:.1}%", basis_points as f64 / 100.0)
}

#[allow(dead_code)]
pub fn format_duration_secs(secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = MINUTE * 60;
    const DAY: u64 = HOUR * 24;

    if secs >= DAY {
        format!("{}d {}h", secs / DAY, (secs % DAY) / HOUR)
    } else if secs >= HOUR {
        format!("{}h {}m", secs / HOUR, (secs % HOUR) / MINUTE)
    } else if secs >= MINUTE {
        format!("{}m {}s", secs / MINUTE, secs % MINUTE)
    } else {
        format!("{}s", secs)
    }
}

#[allow(dead_code)]
pub fn format_age_millis(now_millis: u64, then_millis: u64) -> String {
    if now_millis < then_millis {
        return "0s".to_string();
    }
    let elapsed_secs = (now_millis - then_millis) / 1000;
    format_duration_secs(elapsed_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(10240), "10 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(format_bytes(10_485_760), "10 MiB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GiB");
        assert_eq!(format_bytes(5_368_709_120), "5.0 GiB");
    }

    #[test]
    fn test_format_rate() {
        assert_eq!(format_rate(0), "0 B/s");
        assert_eq!(format_rate(1024), "1.0 KiB/s");
        assert_eq!(format_rate(2048), "2.0 KiB/s");
        assert_eq!(format_rate(1_048_576), "1.0 MiB/s");
    }

    #[test]
    fn test_format_percent() {
        assert_eq!(format_percent(0), "0.0%");
        assert_eq!(format_percent(5000), "50.0%");
        assert_eq!(format_percent(10000), "100.0%");
        assert_eq!(format_percent(12345), "123.5%");
    }

    #[test]
    fn test_format_duration_secs() {
        assert_eq!(format_duration_secs(0), "0s");
        assert_eq!(format_duration_secs(30), "30s");
        assert_eq!(format_duration_secs(60), "1m 0s");
        assert_eq!(format_duration_secs(90), "1m 30s");
        assert_eq!(format_duration_secs(3600), "1h 0m");
        assert_eq!(format_duration_secs(3661), "1h 1m");
        assert_eq!(format_duration_secs(86400), "1d 0h");
        assert_eq!(format_duration_secs(90061), "1d 1h");
    }

    #[test]
    fn test_format_age_millis() {
        assert_eq!(format_age_millis(5000, 2000), "3s");
        assert_eq!(format_age_millis(65000, 2000), "1m 3s");
        assert_eq!(format_age_millis(2000, 5000), "0s");
        assert_eq!(format_age_millis(100_000, 40_000), "1m 0s");
    }
}
