use regex::Regex;

#[derive(Debug, Clone)]
pub struct ScreeningConfig {
    /// Regex patterns that match malicious paths
    pub path_patterns: Vec<String>,
    /// Substrings that match malicious user agents (case-insensitive)
    pub user_agent_patterns: Vec<String>,
}

impl Default for ScreeningConfig {
    fn default() -> Self {
        Self {
            path_patterns: vec![
                // PHP attacks
                r"\.php\d?$".to_string(),
                r"/vendor/".to_string(),
                r"/phpunit/".to_string(),
                r"eval-stdin".to_string(),
                // .NET attacks
                r"\.aspx?$".to_string(),
                r"\.axd$".to_string(),
                r"/Telerik\.".to_string(),
                // Java attacks
                r"\.jsp$".to_string(),
                r"/jasperserver".to_string(),
                // Git/config exposure
                r"/\.git/".to_string(),
                r"/\.env".to_string(),
                r"/\.aws/".to_string(),
                r"/\.ssh/".to_string(),
                // Windows/RDP
                r"/RDWeb/".to_string(),
                // Router/device admin panels
                r"/webfig/".to_string(),
                r"/ssi\.cgi".to_string(),
                r"\.cc$".to_string(),
                // Monitoring tools
                r"/zabbix/".to_string(),
                // WordPress
                r"/wp-admin".to_string(),
                r"/wp-content".to_string(),
                r"/wp-includes".to_string(),
                r"/xmlrpc\.php".to_string(),
            ],
            user_agent_patterns: vec![
                "libredtail-http".to_string(),
                "zgrab".to_string(),
                "masscan".to_string(),
                "nuclei".to_string(),
                "sqlmap".to_string(),
                "nikto".to_string(),
                "nmap".to_string(),
                "dirbuster".to_string(),
                "gobuster".to_string(),
                "wfuzz".to_string(),
                "ffuf".to_string(),
            ],
        }
    }
}

impl ScreeningConfig {
    pub fn new() -> Self {
        Self {
            path_patterns: Vec::new(),
            user_agent_patterns: Vec::new(),
        }
    }

    pub fn with_path_pattern(mut self, pattern: &str) -> Self {
        self.path_patterns.push(pattern.to_string());
        self
    }

    pub fn with_path_patterns(mut self, patterns: Vec<String>) -> Self {
        self.path_patterns.extend(patterns);
        self
    }

    pub fn with_user_agent_pattern(mut self, pattern: &str) -> Self {
        self.user_agent_patterns.push(pattern.to_string());
        self
    }

    pub fn with_user_agent_patterns(mut self, patterns: Vec<String>) -> Self {
        self.user_agent_patterns.extend(patterns);
        self
    }
}

#[derive(Debug, Clone)]
pub struct ScreeningResult {
    pub reason: ScreeningReason,
}

#[derive(Debug, Clone)]
pub enum ScreeningReason {
    MaliciousPath(String),
    MaliciousUserAgent(String),
}

impl std::fmt::Display for ScreeningReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScreeningReason::MaliciousPath(pattern) => {
                write!(f, "malicious path pattern: {}", pattern)
            }
            ScreeningReason::MaliciousUserAgent(pattern) => {
                write!(f, "malicious user agent: {}", pattern)
            }
        }
    }
}

pub struct RequestScreener {
    path_patterns: Vec<(String, Regex)>,
    user_agent_patterns: Vec<String>,
}

impl RequestScreener {
    pub fn new(config: &ScreeningConfig) -> Result<Self, regex::Error> {
        let path_patterns = config
            .path_patterns
            .iter()
            .map(|p| Ok((p.clone(), Regex::new(p)?)))
            .collect::<Result<Vec<_>, regex::Error>>()?;

        let user_agent_patterns = config
            .user_agent_patterns
            .iter()
            .map(|p| p.to_lowercase())
            .collect();

        Ok(Self {
            path_patterns,
            user_agent_patterns,
        })
    }

    pub fn check(&self, path: &str, user_agent: &str) -> Option<ScreeningResult> {
        // Check path patterns
        for (pattern_str, regex) in &self.path_patterns {
            if regex.is_match(path) {
                return Some(ScreeningResult {
                    reason: ScreeningReason::MaliciousPath(pattern_str.clone()),
                });
            }
        }

        // Check user agent patterns (case-insensitive substring match)
        let user_agent_lower = user_agent.to_lowercase();
        for pattern in &self.user_agent_patterns {
            if user_agent_lower.contains(pattern) {
                return Some(ScreeningResult {
                    reason: ScreeningReason::MaliciousUserAgent(pattern.clone()),
                });
            }
        }

        None
    }
}

impl Clone for RequestScreener {
    fn clone(&self) -> Self {
        Self {
            path_patterns: self.path_patterns.clone(),
            user_agent_patterns: self.user_agent_patterns.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_catches_php() {
        let config = ScreeningConfig::default();
        let screener = RequestScreener::new(&config).unwrap();

        let result = screener.check(
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "Mozilla/5.0",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_default_config_catches_git() {
        let config = ScreeningConfig::default();
        let screener = RequestScreener::new(&config).unwrap();

        let result = screener.check("/.git/config", "Mozilla/5.0");
        assert!(result.is_some());
    }

    #[test]
    fn test_default_config_catches_malicious_user_agent() {
        let config = ScreeningConfig::default();
        let screener = RequestScreener::new(&config).unwrap();

        let result = screener.check("/", "libredtail-http");
        assert!(result.is_some());
    }

    #[test]
    fn test_allows_legitimate_requests() {
        let config = ScreeningConfig::default();
        let screener = RequestScreener::new(&config).unwrap();

        let result = screener.check(
            "/blog/hello-world",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_user_agent_case_insensitive() {
        let config = ScreeningConfig::default();
        let screener = RequestScreener::new(&config).unwrap();

        let result = screener.check("/", "LIBREDTAIL-HTTP");
        assert!(result.is_some());
    }
}
