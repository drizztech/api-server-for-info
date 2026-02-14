use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use crate::vulns;
use anyhow::Result;
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResult {
    pub url: String,
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub js_files: Vec<String>,
    pub html_files: Vec<String>,
    pub vulns: Vec<vulns::Vulnerability>,
}

pub async fn scan_url(client: &Client, target_url: &str) -> Result<ScanResult> {
    let res = client.get(target_url).send().await?;
    let status = res.status();
    let url = res.url().to_string();

    let mut headers_map = std::collections::HashMap::new();
    for (k, v) in res.headers() {
        if let Ok(val_str) = v.to_str() {
            headers_map.insert(k.to_string(), val_str.to_string());
        }
    }

    let mut vulns = vulns::check_headers(res.headers());
    vulns.extend(vulns::check_api_heuristics(&url, "GET", status.as_u16()));

    let body = res.text().await.unwrap_or_default();
    let document = Html::parse_document(&body);

    let mut js_files = Vec::new();
    let script_selector = Selector::parse("script[src]").unwrap();
    for element in document.select(&script_selector) {
        if let Some(src) = element.value().attr("src") {
             if let Ok(abs_url) = resolve_url(&url, src) {
                 js_files.push(abs_url);
             } else {
                 js_files.push(src.to_string());
             }
        }
    }

    let mut html_files = Vec::new();
    let link_selector = Selector::parse("a[href]").unwrap();
    for element in document.select(&link_selector) {
        if let Some(href) = element.value().attr("href") {
            // Primitive check for html files or just pages
            if href.ends_with(".html") || href.ends_with(".htm") || !href.contains('.') {
                 if let Ok(abs_url) = resolve_url(&url, href) {
                     html_files.push(abs_url);
                 } else {
                     html_files.push(href.to_string());
                 }
            }
        }
    }

    Ok(ScanResult {
        url,
        status: status.as_u16(),
        headers: headers_map,
        js_files,
        html_files,
        vulns,
    })
}

fn resolve_url(base: &str, relative: &str) -> Result<String> {
    let base_url = Url::parse(base)?;
    let joined = base_url.join(relative)?;
    Ok(joined.to_string())
}
