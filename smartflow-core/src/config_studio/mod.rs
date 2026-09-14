pub mod discovery;
pub mod fingerprint;
pub mod model;
pub mod patch;
pub mod semantic;
pub mod validation;
pub mod writer;

pub use discovery::{validate_safe_config_path, ConfigDiscoveryScanner};
pub use fingerprint::FingerprintDetector;
pub use model::{
    AstPatchItem, ConfigDocument, ConfigFileSummary, ConfigFormat, ConfigPatchRequest,
    ConfigSaveResult, ConfigValidationResult, PortConflictInfo, SemanticConfig, SemanticEndpoint,
    SemanticListener,
};
pub use patch::AstPatcher;
pub use semantic::SemanticExtractor;
pub use validation::ConfigValidator;
pub use writer::SafeConfigWriter;

#[cfg(test)]
mod tests;
