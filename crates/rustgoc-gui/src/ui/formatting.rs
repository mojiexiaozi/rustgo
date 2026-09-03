#![forbid(unsafe_code)]

pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
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
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1_048_576), "1.00 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.00 GB");
        assert_eq!(format_bytes(5_368_709_120), "5.00 GB");
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
