use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct Vulnerability {
    pub check_type: String,
    pub message: String,
    pub severity: String, // Low, Medium, High, Critical
}

pub fn check_headers(headers: &reqwest::header::HeaderMap) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    if !headers.contains_key("Strict-Transport-Security") {
        vulns.push(Vulnerability {
            check_type: "Header".to_string(),
            message: "Missing Strict-Transport-Security header".to_string(),
            severity: "Low".to_string(),
        });
    }

    if !headers.contains_key("Content-Security-Policy") {
        vulns.push(Vulnerability {
            check_type: "Header".to_string(),
            message: "Missing Content-Security-Policy header".to_string(),
            severity: "Low".to_string(),
        });
    }

    if let Some(server) = headers.get("Server") {
        vulns.push(Vulnerability {
            check_type: "Info".to_string(),
            message: format!("Server header revealed: {:?}", server),
            severity: "Info".to_string(),
        });
    }

    if let Some(powered) = headers.get("X-Powered-By") {
        vulns.push(Vulnerability {
            check_type: "Info".to_string(),
            message: format!("X-Powered-By header revealed: {:?}", powered),
            severity: "Info".to_string(),
        });
    }

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    #[test]
    fn test_missing_headers() {
        let headers = HeaderMap::new();
        let vulns = check_headers(&headers);
        assert!(vulns.iter().any(|v| v.message.contains("Missing Strict-Transport-Security")));
        assert!(vulns.iter().any(|v| v.message.contains("Missing Content-Security-Policy")));
    }

    #[test]
    fn test_info_disclosure() {
        let mut headers = HeaderMap::new();
        headers.insert("Server", "Apache".parse().unwrap());
        let vulns = check_headers(&headers);
        assert!(vulns.iter().any(|v| v.message.contains("Server header revealed")));
    }
}

pub fn check_api_heuristics(url: &str, method: &str, status: u16) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    // Example heuristic: 500 error on API might indicate unhandled exception/logic error
    if status >= 500 && url.contains("/api/") {
        vulns.push(Vulnerability {
            check_type: "API Logic".to_string(),
            message: format!("API Endpoint returned 5xx error: {} {}", method, status),
            severity: "Medium".to_string(),
        });
    }

    vulns
}
