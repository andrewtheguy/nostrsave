use std::path::PathBuf;

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

/// Config file locations to check (in order)
fn config_file_paths() -> Vec<PathBuf> {
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

/// Load relays from config file
fn load_from_config_file() -> Option<Vec<String>> {
    for path in config_file_paths() {
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

/// Get default relays with priority: env var > config file > fallback
pub fn get_default_relays() -> Vec<String> {
    // Priority 1: Environment variable
    if let Some(relays) = load_from_env() {
        return relays;
    }

    // Priority 2: Config file
    if let Some(relays) = load_from_config_file() {
        return relays;
    }

    // Priority 3: Fallback defaults
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
