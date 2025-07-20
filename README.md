# Conan - OSINT tool 

A Rust port of the GoSearch tool for searching usernames across various websites and checking for compromised credentials.

## Features

- **Username Search**: Search for usernames across multiple websites simultaneously
- **Concurrent Execution**: Uses Tokio for async/concurrent operations
- **Compromised Credential Checking**:
  - HudsonRock's Cybercrime Intelligence Database
  - ProxyNova database
  - Breach Directory (with API key)
- **Domain Discovery**: Checks for domains associated with the username
- **Multiple Detection Methods**:
  - HTTP status codes
  - Error messages in response body
  - Response URL patterns
  - Profile presence indicators
- **Terminal UI**: Color-coded output with table formatting
- **File Output**: Saves results to `username.txt`

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo

### Build from Source

```bash
git clone https://github.com/yourusername/gosearch-rust
cd gosearch-rust
cargo build --release
```

The binary will be available at `target/release/gosearch`

## Usage

### Basic Usage

```bash
# Search for a username
gosearch -u username

# Or use positional argument
gosearch username
```

### Advanced Options

```bash
# Exclude false positives
gosearch -u username --no-false-positives

# Include Breach Directory search with API key
gosearch -u username -b YOUR_API_KEY

# Or use long form
gosearch -u username --breach-directory YOUR_API_KEY
```

### Command Line Options

- `-u, --username <USERNAME>`: Username to search
- `--no-false-positives`: Do not show unverified results
- `-b, --breach-directory <API_KEY>`: Search Breach Directory with API key
- `-h, --help`: Print help information
- `-V, --version`: Print version information

## Output

The tool provides:
1. **Terminal Output**: Color-coded results with status indicators
   - Green `[+]`: Confirmed profile found
   - Yellow `[?]`: Possible profile (unverified)
   - Red `[-]`: No profile or error
2. **File Output**: Results saved to `username.txt`

## Project Structure

```
gosearch-rust/
├── Cargo.toml          # Project configuration
├── src/
│   ├── main.rs         # Main application entry point
│   ├── lib.rs          # Library module exports
│   ├── models.rs       # Data structures
│   ├── breach_directory.rs  # Breach Directory API client
│   └── utils.rs        # Utility functions
└── README.md           # This file
```

## Differences from Go Version

This Rust implementation maintains feature parity with the original Go version with some improvements:

1. **Type Safety**: Leverages Rust's type system for safer code
2. **Error Handling**: Uses Result types for better error propagation
3. **Memory Safety**: No manual memory management required
4. **Performance**: Comparable performance with potential for optimization
5. **Dependencies**: Uses well-maintained Rust crates instead of Go packages

### Dependency Mapping

| Go Package | Rust Crate | Purpose |
|------------|------------|---------|
| `github.com/bytedance/sonic` | `serde_json` | JSON parsing |
| `github.com/inancgumus/screen` | Custom implementation | Screen clearing |
| `github.com/olekukonko/tablewriter` | `comfy-table` | Table formatting |
| `github.com/andybalholm/brotli` | `reqwest` (built-in) | Brotli decompression |
| `github.com/fatih/color` | `colored` | Terminal colors |

## Building for Different Platforms

```bash
# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# Windows
cargo build --release --target x86_64-pc-windows-msvc

# macOS
cargo build --release --target x86_64-apple-darwin
```

## Performance Considerations

- Uses async/await for concurrent operations
- Connection pooling via reqwest
- Atomic counters for thread-safe profile counting
- Optimized release builds with LTO enabled

## Contributing

Contributions are welcome! Please ensure:
1. Code follows Rust conventions (`cargo clippy`)
2. Tests pass (`cargo test`)
3. Format code (`cargo fmt`)

## License

This project maintains the same license as the original GoSearch project.

## Acknowledgments

- Original GoSearch project by ibnaleem
- All contributors to the dependencies used
