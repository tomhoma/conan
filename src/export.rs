use anyhow::Result;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Serialize, Debug, Clone)]
pub struct SearchResult {
    pub username: String,
    pub url: String,
    pub platform: String,
    pub found: bool,
}

#[derive(Serialize, Debug)]
pub struct ExportData {
    pub username: String,
    pub total_profiles: u32,
    pub timestamp: String,
    pub results: Vec<SearchResult>,
}

impl ExportData {
    pub fn new(username: String, total_profiles: u32) -> Self {
        Self {
            username,
            total_profiles,
            timestamp: chrono::Utc::now().to_rfc3339(),
            results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, url: String, platform: String, found: bool) {
        self.results.push(SearchResult {
            username: self.username.clone(),
            url,
            platform,
            found,
        });
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn to_csv(&self) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("Username,Platform,URL,Found,Timestamp\n");

        for result in &self.results {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                self.username,
                result.platform,
                result.url,
                result.found,
                self.timestamp
            ));
        }

        Ok(csv)
    }

    pub fn save_json(&self, filename: &str) -> Result<()> {
        let mut file = File::create(filename)?;
        file.write_all(self.to_json()?.as_bytes())?;
        Ok(())
    }

    pub fn save_csv(&self, filename: &str) -> Result<()> {
        let mut file = File::create(filename)?;
        file.write_all(self.to_csv()?.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_json() {
        let mut export = ExportData::new("testuser".to_string(), 2);
        export.add_result("https://github.com/testuser".to_string(), "GitHub".to_string(), true);
        export.add_result("https://twitter.com/testuser".to_string(), "Twitter".to_string(), true);

        let json = export.to_json().unwrap();
        assert!(json.contains("testuser"));
        assert!(json.contains("GitHub"));
    }

    #[test]
    fn test_export_csv() {
        let mut export = ExportData::new("testuser".to_string(), 1);
        export.add_result("https://github.com/testuser".to_string(), "GitHub".to_string(), true);

        let csv = export.to_csv().unwrap();
        assert!(csv.contains("Username,Platform,URL,Found,Timestamp"));
        assert!(csv.contains("testuser,GitHub"));
    }
}
