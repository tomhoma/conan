
use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};

pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

pub fn print_separator() {
    println!("{}", "⎯".repeat(85));
}

pub fn write_to_file(username: &str, content: &str, file_mutex: &Arc<Mutex<()>>) -> Result<()> {
    let _guard = file_mutex
        .lock()
        .map_err(|e| anyhow::anyhow!("Failed to acquire file mutex lock: {}", e))?;

    let filename = format!("{}.txt", username);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)?;

    writeln!(file, "{}", content)?;
    Ok(())
}