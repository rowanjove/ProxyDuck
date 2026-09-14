pub mod manager;
pub mod model;

pub use manager::TimelineManager;
pub use model::{EventCategory, EventSeverity, NetworkEvent, TimelineFilter};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_record_and_query_filter() {
        let manager = TimelineManager::new(10);
        manager.record(
            EventCategory::Adapter,
            EventSeverity::Info,
            "system",
            "Wi-Fi Connected",
            "SSID: Home",
            Some("Wi-Fi".to_string()),
        );
        manager.record(
            EventCategory::Endpoint,
            EventSeverity::Warning,
            "supervisor",
            "Endpoint Timeout",
            "127.0.0.1:7897 timed out",
            Some("local-socks".to_string()),
        );

        let events = manager.query(None);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].title, "Endpoint Timeout"); // Reversed order (newest first)

        let filter = TimelineFilter {
            category: Some(EventCategory::Endpoint),
            ..Default::default()
        };
        let filtered = manager.query(Some(&filter));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].title, "Endpoint Timeout");
    }
}
