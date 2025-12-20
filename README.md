# Rust MITM Proxy for mpv

A high-performance MITM proxy that enables seamless YouTube streaming in mpv, with optional support for upstream proxies and automatic stream optimization.

## Features

- **MITM Proxy**: Re-signs HTTPS traffic on the fly using an ephemeral internal CA.
- **Stream Optimization**: Transparently modifies specific request headers to ensure consistent stream delivery and compatibility with various network environments.
- **Optional Upstream Support**: Can connect to an upstream SOCKS5 proxy if needed.
- **mpv Integration**: Includes a Lua script for seamless integration with the mpv media player.
- **Performance**: Built with Rust and Tokio for high performance and low resource usage.

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable)
- [mpv](https://mpv.io/)
- (Optional) An upstream **SOCKS5** proxy (Note: HTTP/HTTPS upstream proxies are not supported)

## Installation

### 1. Download or Build

#### Download
Download the latest release for your platform. The package contains:
- `main.lua` (The mpv script)
- `mpv-mitm-proxy` (The proxy binary)

#### Build
If you prefer to build from source:
```bash
cargo build --release
```
The binary will be located at `target/release/mpv-mitm-proxy`.

### 2. Install to mpv

Create a new folder named `mpv-mitm-proxy` inside your mpv `scripts` directory:
- **Linux/macOS**: `~/.config/mpv/scripts/mpv-mitm-proxy/`
- **Windows**: `%APPDATA%\mpv\scripts\mpv-mitm-proxy\`

Place both the binary (`mpv-mitm-proxy` or `mpv-mitm-proxy.exe`) and the Lua script (`main.lua` or `mitm_rust_proxy.lua`) into that folder.

### 3. Configuration (Optional)

You can modify the upstream proxy settings at the top of the Lua script:

- **Direct connection (No upstream)**:
  ```lua
  local upstream_socks5_url = ""
  ```
- **Upstream SOCKS5 proxy**:
  ```lua
  local upstream_socks5_url = "socks5://127.0.0.1:1080"
  ```

## Usage

The script automatically starts and configures the proxy whenever you open a URL that triggers `yt-dlp` in mpv.

Press `Shift+P` (P) in mpv to check the proxy status.

## Security

The proxy utilizes an **ephemeral internal Certificate Authority (CA)** to re-sign traffic on the fly. This CA is generated in memory when the proxy starts and is not persisted to disk. This ensures that no sensitive CA keys are left behind on your system and provides a lightweight, secure approach for local traffic interception.

## License

MIT
