use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Arc};

use super::model::{NetworkDiagnosis, OverallStatus};

const DEFAULT_MAX_HISTORY: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticHistorySummary {
    pub timestamp: String,
    pub status: OverallStatus,
    pub issues_count: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub primary_issue: Option<String>,
}

pub struct DiagnosticHistory {
    max_items: usize,
    records: RwLock<VecDeque<NetworkDiagnosis>>,
}

impl DiagnosticHistory {
    pub fn new(max_items: usize) -> Self {
        Self {
            max_items: if max_items == 0 {
                DEFAULT_MAX_HISTORY
            } else {
                max_items
            },
            records: RwLock::new(VecDeque::with_capacity(max_items)),
        }
    }

    pub fn record(&self, diagnosis: NetworkDiagnosis) {
        let mut list = self.records.write();
        list.push_back(diagnosis);
        while list.len() > self.max_items {
            list.pop_front();
        }
    }

    pub fn list_summaries(&self) -> Vec<DiagnosticHistorySummary> {
        let list = self.records.read();
        list.iter()
            .rev()
            .map(|diag| {
                let critical = diag
                    .issues
                    .iter()
                    .filter(|i| i.severity == super::model::Severity::Critical)
                    .count();
                let warning = diag
                    .issues
                    .iter()
                    .filter(|i| i.severity == super::model::Severity::Warning)
                    .count();
                let primary_issue = diag.issues.first().map(|i| i.title.clone());

                DiagnosticHistorySummary {
                    timestamp: diag.timestamp.clone(),
                    status: diag.status,
                    issues_count: diag.issues.len(),
                    critical_count: critical,
                    warning_count: warning,
                    primary_issue,
                }
            })
            .collect()
    }

    pub fn latest(&self) -> Option<NetworkDiagnosis> {
        let list = self.records.read();
        list.back().cloned()
    }

    pub fn all(&self) -> Vec<NetworkDiagnosis> {
        let list = self.records.read();
        list.iter().cloned().collect()
    }
}

impl Default for DiagnosticHistory {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_HISTORY)
    }
}

pub static GLOBAL_HISTORY: once_cell::sync::Lazy<Arc<DiagnosticHistory>> =
    once_cell::sync::Lazy::new(|| Arc::new(DiagnosticHistory::default()));
