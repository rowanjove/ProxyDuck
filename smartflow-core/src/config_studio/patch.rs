use super::model::AstPatchItem;

pub struct AstPatcher;

impl AstPatcher {
    /// Applies targeted key-value patches to original raw content without altering comments or formatting.
    pub fn apply_patches(original: &str, patches: &[AstPatchItem]) -> (String, String) {
        let mut lines: Vec<String> = original.lines().map(|l| l.to_string()).collect();
        let mut diff_lines = Vec::new();

        for patch in patches {
            let key = &patch.key;
            let old_val = &patch.old_value;
            let new_val = &patch.new_value;

            for line in lines.iter_mut() {
                let trimmed = line.trim();
                // Check YAML style: "key: old_val"
                if trimmed.starts_with(key) && (trimmed.contains(old_val) || old_val.is_empty()) {
                    let old_line = line.clone();
                    // Replace the value part while preserving indentation and key
                    if let Some((k, v)) = line.split_once(':') {
                        if !old_val.is_empty() && v.contains(old_val) {
                            let new_v = v.replacen(old_val, new_val, 1);
                            *line = format!("{k}:{new_v}");
                        } else if let Some((val_part, comment_part)) = v.split_once('#') {
                            let leading_ws: String =
                                val_part.chars().take_while(|c| c.is_whitespace()).collect();
                            let ws = if leading_ws.is_empty() {
                                " "
                            } else {
                                &leading_ws
                            };
                            *line = format!("{k}:{ws}{new_val} #{comment_part}");
                        } else {
                            let leading_ws: String =
                                v.chars().take_while(|c| c.is_whitespace()).collect();
                            let ws = if leading_ws.is_empty() {
                                " "
                            } else {
                                &leading_ws
                            };
                            *line = format!("{k}:{ws}{new_val}");
                        }
                    } else if let Some((k, v)) = line.split_once('=') {
                        if !old_val.is_empty() && v.contains(old_val) {
                            let new_v = v.replacen(old_val, new_val, 1);
                            *line = format!("{k}={new_v}");
                        } else if let Some((val_part, comment_part)) = v.split_once('#') {
                            let leading_ws: String =
                                val_part.chars().take_while(|c| c.is_whitespace()).collect();
                            let ws = if leading_ws.is_empty() {
                                " "
                            } else {
                                &leading_ws
                            };
                            *line = format!("{k}={ws}{new_val} #{comment_part}");
                        } else {
                            let leading_ws: String =
                                v.chars().take_while(|c| c.is_whitespace()).collect();
                            let ws = if leading_ws.is_empty() {
                                " "
                            } else {
                                &leading_ws
                            };
                            *line = format!("{k}={ws}{new_val}");
                        }
                    } else {
                        *line = line.replace(old_val, new_val);
                    }

                    if old_line != *line {
                        diff_lines.push(format!("- {old_line}"));
                        diff_lines.push(format!("+ {line}"));
                    }
                    break;
                }
            }
        }

        let new_content = lines.join("\n");
        let diff = if diff_lines.is_empty() {
            Self::generate_line_diff(original, &new_content)
        } else {
            diff_lines.join("\n")
        };

        (new_content, diff)
    }

    /// Generates unified-style diff between two text documents.
    pub fn generate_line_diff(original: &str, modified: &str) -> String {
        let orig_lines: Vec<&str> = original.lines().collect();
        let mod_lines: Vec<&str> = modified.lines().collect();
        let mut diff = Vec::new();

        let max_len = orig_lines.len().max(mod_lines.len());
        for i in 0..max_len {
            match (orig_lines.get(i), mod_lines.get(i)) {
                (Some(o), Some(m)) if o != m => {
                    diff.push(format!("- {o}"));
                    diff.push(format!("+ {m}"));
                }
                (Some(o), None) => {
                    diff.push(format!("- {o}"));
                }
                (None, Some(m)) => {
                    diff.push(format!("+ {m}"));
                }
                _ => {}
            }
        }

        diff.join("\n")
    }
}
