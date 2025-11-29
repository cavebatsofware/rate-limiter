/*  This file is part of basic-axum-rate-limit
 *  Copyright (C) 2025  Grant DeFayette
 *
 *  basic-axum-rate-limit is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  basic-axum-rate-limit is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with basic-axum-rate-limit.  If not, see <https://www.gnu.org/licenses/>.
 */

use regex::RegexSet;

#[derive(Debug, Clone, Default)]
pub struct ScreeningConfig {
    /// Regex patterns that match malicious paths
    pub path_patterns: Vec<String>,
    /// Regex patterns that match malicious user agents (case-insensitive)
    pub user_agent_patterns: Vec<String>,
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

#[derive(Clone)]
pub struct RequestScreener {
    path_regex_set: RegexSet,
    path_patterns: Vec<String>,
    user_agent_regex_set: RegexSet,
    user_agent_patterns: Vec<String>,
}

impl RequestScreener {
    pub fn new(config: &ScreeningConfig) -> Result<Self, regex::Error> {
        let path_regex_set = RegexSet::new(&config.path_patterns)?;

        // Make UA patterns case-insensitive
        let ua_regexes: Vec<String> = config
            .user_agent_patterns
            .iter()
            .map(|p| format!("(?i){}", p))
            .collect();

        let user_agent_regex_set = RegexSet::new(&ua_regexes)?;

        Ok(Self {
            path_regex_set,
            path_patterns: config.path_patterns.clone(),
            user_agent_regex_set,
            user_agent_patterns: config.user_agent_patterns.clone(),
        })
    }

    pub fn check(&self, path: &str, user_agent: &str) -> Option<ScreeningResult> {
        // Single-pass check against all path patterns
        if let Some(idx) = self.path_regex_set.matches(path).iter().next() {
            return Some(ScreeningResult {
                reason: ScreeningReason::MaliciousPath(self.path_patterns[idx].clone()),
            });
        }

        // Single-pass check against all user agent patterns (no allocation)
        if let Some(idx) = self.user_agent_regex_set.matches(user_agent).iter().next() {
            return Some(ScreeningResult {
                reason: ScreeningReason::MaliciousUserAgent(self.user_agent_patterns[idx].clone()),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ScreeningConfig {
        ScreeningConfig::new()
            .with_path_patterns(vec![
                r"\.php\d?$".to_string(),
                r"/vendor/".to_string(),
                r"/\.git/".to_string(),
            ])
            .with_user_agent_patterns(vec!["libredtail-http".to_string()])
    }

    #[test]
    fn test_catches_php() {
        let screener = RequestScreener::new(&test_config()).unwrap();

        let result = screener.check(
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "Mozilla/5.0",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_catches_git() {
        let screener = RequestScreener::new(&test_config()).unwrap();

        let result = screener.check("/.git/config", "Mozilla/5.0");
        assert!(result.is_some());
    }

    #[test]
    fn test_catches_malicious_user_agent() {
        let screener = RequestScreener::new(&test_config()).unwrap();

        let result = screener.check("/", "libredtail-http");
        assert!(result.is_some());
    }

    #[test]
    fn test_allows_legitimate_requests() {
        let screener = RequestScreener::new(&test_config()).unwrap();

        let result = screener.check(
            "/blog/hello-world",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_user_agent_case_insensitive() {
        let screener = RequestScreener::new(&test_config()).unwrap();

        let result = screener.check("/", "LIBREDTAIL-HTTP");
        assert!(result.is_some());
    }

    #[test]
    fn test_default_config_is_empty() {
        let config = ScreeningConfig::default();
        assert!(config.path_patterns.is_empty());
        assert!(config.user_agent_patterns.is_empty());
    }
}
