use std::{fs, path::Path};

use crate::config_studio::{
    fingerprint::FingerprintDetector,
    model::{AstPatchItem, ConfigFormat},
    patch::AstPatcher,
    semantic::SemanticExtractor,
    validation::ConfigValidator,
    writer::SafeConfigWriter,
};

#[test]
fn test_clash_yaml_fingerprint() {
    let sample_clash = r#"
        port: 7890
        socks-port: 7891
        mixed-port: 7892
        proxies:
          - name: "Node 1"
            type: socks5
            server: 127.0.0.1
            port: 1080
        rules:
          - MATCH,DIRECT
        "#;

    let res = FingerprintDetector::detect(Path::new("config.yaml"), sample_clash);
    assert_eq!(res.format, ConfigFormat::Yaml);
    assert!(res.fingerprint.contains("Clash"));
    assert!(res.editable);
}

#[test]
fn test_sing_box_json_fingerprint() {
    let sample_sing_box = r#"{
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen_port": 2080
                }
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ]
        }"#;

    let res = FingerprintDetector::detect(Path::new("sing-box.json"), sample_sing_box);
    assert_eq!(res.format, ConfigFormat::Json);
    assert!(res.fingerprint.contains("sing-box"));
}

#[test]
fn test_non_destructive_ast_patch() {
    let raw_yaml = r#"# User main config
mixed-port: 7890 # Do not change without reason
# Proxies definition
proxies:
  - name: test
    type: socks5
"#;

    let patch = AstPatchItem {
        key: "mixed-port".to_string(),
        old_value: "7890".to_string(),
        new_value: "7895".to_string(),
    };

    let (new_content, diff) = AstPatcher::apply_patches(raw_yaml, &[patch]);

    // Verify comments and structure were NOT destroyed
    assert!(new_content.contains("# User main config"));
    assert!(new_content.contains("# Do not change without reason"));
    assert!(new_content.contains("# Proxies definition"));
    assert!(new_content.contains("mixed-port: 7895"));
    assert!(!new_content.contains("mixed-port: 7890"));

    // Verify diff
    assert!(diff.contains("- mixed-port: 7890"));
    assert!(diff.contains("+ mixed-port: 7895"));
}

#[test]
fn test_semantic_extraction() {
    let sample_clash = r#"
        mixed-port: 7890
        proxies:
          - name: "Node A"
            type: socks5
            server: 1.2.3.4
            port: 1080
        rules:
          - DOMAIN-SUFFIX,google.com,Node A
          - MATCH,DIRECT
        "#;

    let semantic = SemanticExtractor::extract(sample_clash, ConfigFormat::Yaml);
    assert_eq!(semantic.inbound_listeners.len(), 1);
    assert_eq!(semantic.inbound_listeners[0].port, 7890);
    assert_eq!(semantic.outbound_endpoints.len(), 1);
    assert_eq!(semantic.outbound_endpoints[0].name, "Node A");
    assert_eq!(semantic.routing_rules_count, 2);
}

#[test]
fn test_syntax_validation() {
    let bad_yaml = "mixed-port: [unclosed bracket";
    let semantic = SemanticExtractor::extract(bad_yaml, ConfigFormat::Yaml);
    let res = ConfigValidator::validate(bad_yaml, ConfigFormat::Yaml, &semantic);
    assert!(!res.valid);
    assert!(!res.errors.is_empty());
}

#[test]
fn test_concurrency_conflict_protection() {
    let dir = std::env::temp_dir().join(format!("proxyduck_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let file_path = dir.join("test_config.yaml");

    let original_text = "mixed-port: 7890\n";
    fs::write(&file_path, original_text).expect("write initial file");

    let correct_hash = FingerprintDetector::compute_hash(original_text);

    // Attempt save with wrong expected_sha256 (simulating external modification)
    let save_res = SafeConfigWriter::save(
        &file_path,
        "stale_wrong_hash_12345",
        "mixed-port: 7899\n",
        ConfigFormat::Yaml,
    );

    assert!(save_res.is_err());
    let err_msg = save_res.err().unwrap().to_string();
    assert!(err_msg.contains("并发修改冲突"));

    // Attempt save with correct hash -> succeeds
    let valid_save = SafeConfigWriter::save(
        &file_path,
        &correct_hash,
        "mixed-port: 7899\n",
        ConfigFormat::Yaml,
    );
    assert!(valid_save.is_ok());
    assert!(file_path.with_extension("yaml.bak").exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_validate_safe_config_path() {
    use crate::config_studio::discovery::validate_safe_config_path;

    let temp_dir = std::env::temp_dir();
    let valid_file = temp_dir.join("test_proxy_cfg.json");
    let _ = fs::write(&valid_file, "{}");

    let res = validate_safe_config_path(&valid_file);
    assert!(res.is_ok());

    // Invalid extension
    let exe_file = temp_dir.join("malware.exe");
    assert!(validate_safe_config_path(&exe_file).is_err());

    // Empty path
    assert!(validate_safe_config_path(Path::new("")).is_err());

    // System directories
    #[cfg(target_os = "windows")]
    {
        let sys_file = Path::new(r"C:\Windows\System32\drivers\etc\hosts.json");
        assert!(validate_safe_config_path(sys_file).is_err());
    }

    let _ = fs::remove_file(&valid_file);
}
