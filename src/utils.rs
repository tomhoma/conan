use colored::*;
use std::env;

pub struct Theme {
    pub use_light_theme: bool,
}

impl Theme {
    pub fn detect() -> Self {
        let colorfgbg = env::var("COLORFGBG").unwrap_or_default();
        let use_light_theme = colorfgbg.contains(";0");
        Self { use_light_theme }
    }
    
    pub fn format_success(&self, text: &str) -> ColoredString {
        if self.use_light_theme {
            text.bright_green()
        } else {
            text.green()
        }
    }
    
    pub fn format_error(&self, text: &str) -> ColoredString {
        if self.use_light_theme {
            text.bright_red()
        } else {
            text.red()
        }
    }
    
    pub fn format_warning(&self, text: &str) -> ColoredString {
        if self.use_light_theme {
            text.bright_yellow()
        } else {
            text.yellow()
        }
    }
    
    pub fn format_info(&self, text: &str) -> ColoredString {
        if self.use_light_theme {
            text.bright_blue()
        } else {
            text.blue()
        }
    }
}

pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

pub fn print_separator() {
    println!("{}", "⎯".repeat(85));
}