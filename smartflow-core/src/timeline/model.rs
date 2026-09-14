use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Adapter,
    Route,
    Dns,
    Proxy,
    Endpoint,
    Policy,
    Engine,
    Core,
    Repair,
    Scenario,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub category: EventCategory,
    pub severity: EventSeverity,
    pub source: String,
    pub title: String,
    pub details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_object: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineFilter {
    pub category: Option<EventCategory>,
    pub severity: Option<EventSeverity>,
    pub source: Option<String>,
    pub search: Option<String>,
    pub limit: Option<usize>,
}
