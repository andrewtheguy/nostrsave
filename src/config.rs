use serde::Deserialize;
use std::path::PathBuf;

// ============================================================================
// TOML Configuration Structs
// ============================================================================

/// Root configuration structure
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub identity: Option<IdentityConfig>,
    pub data_relays: Option<RelaysConfig>,
    pub index_relays: Option<RelaysConfig>,
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

/// Default index relays (verified working relays for manifest/index storage)
const DEFAULT_INDEX_RELAYS: &[&str] = &[
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

// ============================================================================
// Config Loading
// ============================================================================

/// Get the default config file path
pub fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("nostrsave").join("config.toml"))
}

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

/// Expand ~ to home directory in paths
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
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

/// Require config file to exist, returning error with helpful message if not
pub fn require_config() -> anyhow::Result<Config> {
    load_config().ok_or_else(|| {
        let path = default_config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/nostrsave/config.toml".to_string());
        anyhow::anyhow!(
            "Config file required but not found.\n\
             Create config at: {}\n\
             See config.sample.toml for example.",
            path
        )
    })
}

// ============================================================================
// Identity Resolution
// ============================================================================

/// Get private key from config
/// Returns error if config missing or identity not configured
pub fn get_private_key() -> anyhow::Result<String> {
    let config = require_config()?;

    let identity = config.identity.ok_or_else(|| {
        anyhow::anyhow!("Missing [identity] section in config")
    })?;

    // Check for conflicting options
    if identity.private_key.is_some() && identity.key_file.is_some() {
        return Err(anyhow::anyhow!(
            "Config error: cannot specify both 'private_key' and 'key_file' in [identity]"
        ));
    }

    // Inline key
    if let Some(key) = identity.private_key {
        return Ok(key);
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
        return Ok(key);
    }

    Err(anyhow::anyhow!(
        "Missing private key in [identity] section.\n\
         Set either 'private_key' or 'key_file'."
    ))
}

// ============================================================================
// Relay Resolution
// ============================================================================

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
    let without_scheme = url
        .strip_prefix("wss://")
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

/// Validate and filter relay URLs
fn validate_relay_list(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| validate_relay_url(url).ok())
        .collect()
}

/// Get data relays from config (required for upload)
pub fn get_data_relays() -> anyhow::Result<Vec<String>> {
    let config = require_config()?;

    let data_relays = config.data_relays.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing [data_relays] section in config.\n\
             Add data relays for uploading file chunks."
        )
    })?;

    let relays = validate_relay_list(&data_relays.urls);

    if relays.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid relay URLs in [data_relays] section"
        ));
    }

    Ok(relays)
}

/// Get index relays from config, or fallback to defaults
/// Used for listing files and storing manifests
pub fn get_index_relays() -> Vec<String> {
    // Try to load from config
    if let Some(config) = load_config() {
        if let Some(index_relays) = config.index_relays {
            let relays = validate_relay_list(&index_relays.urls);
            if !relays.is_empty() {
                return relays;
            }
        }
    }

    // Fallback to defaults
    DEFAULT_INDEX_RELAYS.iter().map(|s| s.to_string()).collect()
}


// ============================================================================
// Tests
// ============================================================================

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
    fn test_get_index_relays_returns_defaults() {
        // When no config, should return defaults
        let relays = get_index_relays();
        assert!(!relays.is_empty());
        assert!(relays.iter().all(|r| r.starts_with("wss://")));
    }
}
