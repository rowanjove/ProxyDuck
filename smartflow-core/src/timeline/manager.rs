use std::collections::VecDeque;
use std::sync::RwLock;

use chrono::Utc;
use uuid::Uuid;

use super::model::{EventCategory, EventSeverity, NetworkEvent, TimelineFilter};

pub struct TimelineManager {
    capacity: usize,
    events: RwLock<VecDeque<NetworkEvent>>,
}

impl TimelineManager {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(100),
            events: RwLock::new(VecDeque::with_capacity(capacity.max(100))),
        }
    }

    pub fn record(
        &self,
        category: EventCategory,
        severity: EventSeverity,
        source: impl Into<String>,
        title: impl Into<String>,
        details: impl Into<String>,
        related_object: Option<String>,
    ) -> NetworkEvent {
        let event = NetworkEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            category,
            severity,
            source: source.into(),
            title: title.into(),
            details: details.into(),
            related_object,
        };

        let mut queue = self.events.write().unwrap();
        if queue.len() >= self.capacity {
            queue.pop_front();
        }
        queue.push_back(event.clone());

        event
    }

    pub fn query(&self, filter: Option<&TimelineFilter>) -> Vec<NetworkEvent> {
        let queue = self.events.read().unwrap();
        let mut results = Vec::new();

        for e in queue.iter().rev() {
            if let Some(f) = filter {
                if let Some(cat) = f.category {
                    if e.category != cat {
                        continue;
                    }
                }
                if let Some(sev) = f.severity {
                    if e.severity != sev {
                        continue;
                    }
                }
                if let Some(ref src) = f.source {
                    if !e
                        .source
                        .to_ascii_lowercase()
                        .contains(&src.to_ascii_lowercase())
                    {
                        continue;
                    }
                }
                if let Some(ref search) = f.search {
                    let s = search.to_ascii_lowercase();
                    let matches = e.title.to_ascii_lowercase().contains(&s)
                        || e.details.to_ascii_lowercase().contains(&s)
                        || e.related_object
                            .as_deref()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&s);
                    if !matches {
                        continue;
                    }
                }
                if let Some(limit) = f.limit {
                    if results.len() >= limit {
                        break;
                    }
                }
            }
            results.push(e.clone());
        }

        results
    }

    pub fn clear(&self) {
        let mut queue = self.events.write().unwrap();
        queue.clear();
    }
}
