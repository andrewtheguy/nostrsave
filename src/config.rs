use nostr_sdk::Keys;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

// ============================================================================
// Encryption Algorithm
// ============================================================================

/// Encryption algorithm for file chunks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionAlgorithm {
    #[default]
    Nip44,
    None,
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionAlgorithm::Nip44 => write!(f, "nip44"),
            EncryptionAlgorithm::None => write!(f, "none"),
        }
    }
}

impl std::str::FromStr for EncryptionAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nip44" => Ok(EncryptionAlgorithm::Nip44),
            "none" => Ok(EncryptionAlgorithm::None),
            _ => Err(format!("Invalid encryption algorithm: '{}'. Use 'nip44' or 'none'", s)),
        }
    }
}

// ============================================================================
// TOML Configuration Structs
// ============================================================================

/// Root configuration structure
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub identity: Option<IdentityConfig>,
    pub data_relays: Option<RelaysConfig>,
    pub index_relays: Option<RelaysConfig>,
    pub encryption: Option<EncryptionConfig>,
}

/// Encryption configuration
#[derive(Debug, Deserialize)]
pub struct EncryptionConfig {
    pub algorithm: EncryptionAlgorithm,
}

/// Identity configuration (private key)
#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
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
    "wss://nos.lol",
    //"wss://relay.damus.io", // acceptable for index queries; not recommended for high-volume operations due to rate limiting
    //"wss://relay.nostr.band",
    "wss://relay.nostr.net",
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

/// Get the default config file path (~/.config/nostrsave/config.toml)
pub fn default_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".config").join("nostrsave").join("config.toml"))
}

/// TOML config file locations to check (in order)
fn toml_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        // ~/.config/nostrsave/config.toml (primary)
        paths.push(home.join(".config").join("nostrsave").join("config.toml"));

        // ~/.nostrsave/config.toml (fallback)
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
            match std::fs::read_to_string(&path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(config) => return Some(config),
                    Err(e) => {
                        eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
                    }
                },
                Err(e) => {
                    eprintln!("Warning: Failed to read {}: {}", path.display(), e);
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

/// Read and validate private key from a key file path
fn read_key_file(key_path: &str) -> anyhow::Result<String> {
    let path = expand_tilde(key_path);
    let content = std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!("Failed to read key file '{}': {}", path.display(), e)
    })?;
    let key = content.trim().to_string();
    if key.is_empty() {
        return Err(anyhow::anyhow!("Key file is empty: {}", path.display()));
    }

    // Validate key format (hex or bech32 nsec)
    Keys::parse(&key).map_err(|e| {
        anyhow::anyhow!(
            "Invalid private key format in '{}': {}. Expected 64-char hex or nsec1... bech32.",
            path.display(),
            e
        )
    })?;

    Ok(key)
}

/// Get private key from CLI override or config
/// Returns error if no key file specified
pub fn get_private_key(key_file_override: Option<&str>) -> anyhow::Result<String> {
    // CLI override takes precedence
    if let Some(key_path) = key_file_override {
        return read_key_file(key_path);
    }

    // Fall back to config
    let config = require_config()?;

    let identity = config.identity.ok_or_else(|| {
        anyhow::anyhow!("Missing [identity] section in config")
    })?;

    let key_path = identity.key_file.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing 'key_file' in [identity] section.\n\
             Set key_file in config or use --key-file flag."
        )
    })?;

    read_key_file(&key_path)
}

// ============================================================================
// Relay Resolution
// ============================================================================

/// Validate a relay URL using proper URL parsing
fn validate_relay_url(input: &str) -> Result<String, String> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err("Empty URL".to_string());
    }

    // Parse URL using the url crate
    let parsed = Url::parse(trimmed)
        .map_err(|e| format!("Invalid URL '{}': {}", trimmed, e))?;

    // Validate scheme is wss or ws
    let scheme = parsed.scheme();
    if scheme != "wss" && scheme != "ws" {
        return Err(format!(
            "Invalid scheme '{}' (expected 'wss' or 'ws'): {}",
            scheme, trimmed
        ));
    }

    // Validate host is present and well-formed
    let host = parsed
        .host_str()
        .ok_or_else(|| "Missing host".to_string())?;

    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return Err(format!("Invalid host '{}': {}", host, trimmed));
    }

    Ok(trimmed.to_string())
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
// Encryption Resolution
// ============================================================================

/// Get encryption algorithm from config, or return default (Nip44)
pub fn get_encryption_algorithm() -> EncryptionAlgorithm {
    if let Some(config) = load_config() {
        if let Some(encryption) = config.encryption {
            return encryption.algorithm;
        }
    }
    EncryptionAlgorithm::default()
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
