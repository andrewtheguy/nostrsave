use serde::Deserialize;
use std::path::PathBuf;

// ============================================================================
// TOML Configuration Structs
// ============================================================================

/// Root configuration structure
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub identity: Option<IdentityConfig>,
    pub relays: Option<RelaysConfig>,
}

/// Identity configuration (private key)
#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    /// Inline private key (hex or nsec)
    pub private_key: Option<String>,
    /// Path to file containing private key (supports ~ expansion)
    pub key_file: Option<String>,
}

/// Relay configuration
#[derive(Debug, Deserialize)]
pub struct RelaysConfig {
    pub urls: Vec<String>,
}

// ============================================================================
// Constants
// ============================================================================

/// Fallback relays if none configured (verified working relays)
const FALLBACK_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.wine",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

/// Custom event kind for file chunks (parameterized replaceable)
pub const CHUNK_EVENT_KIND: u16 = 30078;

/// Custom event kind for file manifest (parameterized replaceable)
pub const MANIFEST_EVENT_KIND: u16 = 30079;

/// Custom event kind for file index (parameterized replaceable)
pub const FILE_INDEX_EVENT_KIND: u16 = 30080;

/// Environment variable for relay list (comma-separated)
const RELAY_ENV_VAR: &str = "NOSTRSAVE_RELAYS";

/// TOML config file locations to check (in order)
fn toml_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // ~/.config/nostrsave/config.toml
    if let Some(config_dir) = dirs::config_dir() {
        paths.push(config_dir.join("nostrsave").join("config.toml"));
    }

    // ~/.nostrsave/config.toml
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".nostrsave").join("config.toml"));
    }

    paths
}

/// Legacy relay config file locations (for backward compatibility)
fn legacy_relay_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // ~/.config/nostrsave/relays.txt
    if let Some(config_dir) = dirs::config_dir() {
        paths.push(config_dir.join("nostrsave").join("relays.txt"));
    }

    // ~/.nostrsave/relays.txt
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".nostrsave").join("relays.txt"));
    }

    paths
}

/// Expand ~ to home directory in paths
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

/// Load TOML configuration from file
pub fn load_config() -> Option<Config> {
    for path in toml_config_paths() {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                match toml::from_str(&content) {
                    Ok(config) => return Some(config),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
                    }
                }
            }
        }
    }
    None
}

/// Resolve private key from config file
/// Returns Ok(Some(key)) if found, Ok(None) if not configured, Err on errors
pub fn resolve_key_from_config() -> anyhow::Result<Option<String>> {
    let Some(config) = load_config() else {
        return Ok(None);
    };

    let Some(identity) = config.identity else {
        return Ok(None);
    };

    // Check for conflicting options
    if identity.private_key.is_some() && identity.key_file.is_some() {
        return Err(anyhow::anyhow!(
            "Config error: cannot specify both 'private_key' and 'key_file' in [identity]"
        ));
    }

    // Inline key
    if let Some(key) = identity.private_key {
        return Ok(Some(key));
    }

    // Key file with tilde expansion
    if let Some(key_path) = identity.key_file {
        let path = expand_tilde(&key_path);
        let content = std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!("Failed to read key file '{}': {}", path.display(), e)
        })?;
        let key = content.trim().to_string();
        if key.is_empty() {
            return Err(anyhow::anyhow!("Key file is empty: {}", path.display()));
        }
        return Ok(Some(key));
    }

    Ok(None)
}

/// Validate a relay URL
fn validate_relay_url(url: &str) -> Result<String, String> {
    let url = url.trim();

    if url.is_empty() {
        return Err("Empty URL".to_string());
    }

    // Must start with wss:// or ws://
    if !url.starts_with("wss://") && !url.starts_with("ws://") {
        return Err(format!("Invalid scheme (expected wss:// or ws://): {}", url));
    }

    // Basic URL structure validation
    let without_scheme = url.strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap();

    if without_scheme.is_empty() {
        return Err("Missing host".to_string());
    }

    // Check for valid host characters
    let host_part = without_scheme.split('/').next().unwrap();
    if host_part.is_empty() || host_part.starts_with('.') || host_part.ends_with('.') {
        return Err(format!("Invalid host: {}", url));
    }

    Ok(url.to_string())
}

/// Load relays from environment variable
fn load_from_env() -> Option<Vec<String>> {
    std::env::var(RELAY_ENV_VAR).ok().map(|val| {
        val.split(',')
            .filter_map(|s| validate_relay_url(s).ok())
            .collect()
    }).filter(|v: &Vec<String>| !v.is_empty())
}

/// Load relays from TOML config
fn load_relays_from_toml() -> Option<Vec<String>> {
    let config = load_config()?;
    let relays_config = config.relays?;

    let relays: Vec<String> = relays_config
        .urls
        .iter()
        .filter_map(|url| validate_relay_url(url).ok())
        .collect();

    if relays.is_empty() {
        None
    } else {
        Some(relays)
    }
}

/// Load relays from legacy relays.txt file (backward compatibility)
fn load_from_legacy_file() -> Option<Vec<String>> {
    for path in legacy_relay_paths() {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let relays: Vec<String> = content
                    .lines()
                    .map(|line| line.split('#').next().unwrap_or("").trim())
                    .filter(|line| !line.is_empty())
                    .filter_map(|line| validate_relay_url(line).ok())
                    .collect();

                if !relays.is_empty() {
                    return Some(relays);
                }
            }
        }
    }
    None
}

/// Get default relays with priority: env var > TOML config > legacy file > fallback
pub fn get_default_relays() -> Vec<String> {
    // Priority 1: Environment variable
    if let Some(relays) = load_from_env() {
        return relays;
    }

    // Priority 2: TOML config file
    if let Some(relays) = load_relays_from_toml() {
        return relays;
    }

    // Priority 3: Legacy relays.txt file
    if let Some(relays) = load_from_legacy_file() {
        return relays;
    }

    // Priority 4: Fallback defaults
    FALLBACK_RELAYS.iter().map(|s| s.to_string()).collect()
}

/// Validate and filter a list of relay URLs, returning only valid ones
pub fn validate_relays(relays: &[String]) -> Vec<String> {
    relays
        .iter()
        .filter_map(|url| match validate_relay_url(url) {
            Ok(valid) => Some(valid),
            Err(e) => {
                eprintln!("Warning: Invalid relay URL '{}': {}", url, e);
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_relay_url_valid() {
        assert!(validate_relay_url("wss://relay.damus.io").is_ok());
        assert!(validate_relay_url("wss://nos.lol").is_ok());
        assert!(validate_relay_url("ws://localhost:8080").is_ok());
        assert!(validate_relay_url("wss://relay.example.com/path").is_ok());
    }

    #[test]
    fn test_validate_relay_url_invalid() {
        assert!(validate_relay_url("").is_err());
        assert!(validate_relay_url("https://relay.damus.io").is_err());
        assert!(validate_relay_url("relay.damus.io").is_err());
        assert!(validate_relay_url("wss://").is_err());
        assert!(validate_relay_url("wss://.invalid").is_err());
    }

    #[test]
    fn test_get_default_relays_returns_fallback() {
        // When no env or config, should return fallback
        let relays = get_default_relays();
        assert!(!relays.is_empty());
        assert!(relays.iter().all(|r| r.starts_with("wss://")));
    }
}
