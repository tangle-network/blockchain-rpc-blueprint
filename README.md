# Blockchain RPC Blueprint: Secure RPC Gateway

This Tangle Blueprint provides a secure gateway for accessing arbitrary blockchain RPC nodes. It acts as a proxy layer that enforces access control rules defined and managed through Tangle jobs.

## ✨ Features

- **RPC Proxy:** Forwards HTTP and WebSocket JSON-RPC requests to a configured backend node (e.g., Substrate, Ethereum, Polkadot).
- **Firewall:** Controls access based on IP address/CIDR ranges and Account IDs.
- **Job-Based Access Control:**
  - Grant permanent access to specific IPs or Accounts (`allow_access` job).
  - Allow users to gain temporary access, potentially linked to payments (`pay_for_access` job - payment verification needs implementation).
- **Webhook Notifications:** Sends notifications about firewall events (access granted/denied, rules added, etc.) to configured webhook URLs.
- **Configurable:** Define backend RPC URL, listener address, firewall rules, and webhooks via a simple `config.toml` file.
- **Persistent Service:** Runs as a continuous background service alongside the Tangle job processing logic.

## 🔧 Configuration (`config.toml`)

The blueprint requires a `config.toml` file located in the blueprint's configuration directory (determined by the `BlueprintEnvironment` when deployed).

```toml
# Example configuration for the Secure RPC Gateway Blueprint

[rpc]
# Address and port the gateway listens on (HTTP and WebSocket)
listen_addr = "0.0.0.0:8545"

# URL of the backend RPC node to proxy requests to.
# Use http/ws for unencrypted, https/wss for encrypted backends.
# Example: proxy_to_url = "http://localhost:9933" # Local Substrate node
# Example: proxy_to_url = "wss://rpc.polkadot.io"
# Example: proxy_to_url = "http://localhost:8545" # Local Ethereum node (geth/reth)
proxy_to_url = "http://localhost:9933"

# Maximum allowed request body size in bytes (e.g., for large batch requests)
max_body_size_bytes = 10485760 # 10 MB

# Timeout for proxied requests in seconds
request_timeout_secs = 30

[firewall]
# Set to true to disable all IP/Account checks (USE WITH CAUTION!)
allow_unrestricted_access = false

# List of static IP addresses or CIDR ranges allowed permanent access.
# Useful for whitelisting specific frontends (like PolkadotJS apps) or admin IPs.
allow_ips = [
    "127.0.0.1",
    "::1",
    # "192.168.1.0/24", # Example CIDR
    # Add IPs used by common explorers/apps if desired
]

# List of static AccountId32 addresses allowed permanent access.
# These accounts bypass IP checks if identified (e.g., via future token auth).
allow_accounts = [
    # "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", # Example Polkadot address
]

[webhooks]
# List of URLs to send event notifications to (e.g., access granted/denied, rules added).
# Events are sent as POST requests with JSON payloads.
event_urls = [
    # "https://my-monitoring-service.com/webhook/rpc-gateway"
]
```

See `config.toml` in the repository root for a template.

## 🏗️ Build

```bash
cargo build --release -p blockchain-rpc-bin
```

The binary will be located at `./target/release/secure-rpc-gateway`.

## ▶️ Run

1.  **Ensure Backend RPC is Running:** Make sure the blockchain node specified in `proxy_to_url` (in your `config.toml`) is running and accessible.
2.  **Set Up Configuration:** Place your `config.toml` file in the directory the blueprint expects (this depends on your deployment environment setup, often `./data/config/config.toml` relative to where the blueprint runs).
3.  **Run the Binary:**
    ```bash
    ./target/release/secure-rpc-gateway
    ```
    The gateway will start listening on the `listen_addr` and connect to the Tangle network to process jobs.

## 🛠️ Jobs

Interact with the running blueprint by submitting jobs to the Tangle network associated with its Service ID.

- **`ALLOW_ACCESS_JOB_ID` (0):** Grant permanent access.
  - **Input Type:** `AllowAccessInput { target: AccessTarget }`
  - `AccessTarget::Ip(String)`: IP address or CIDR range (e.g., "192.168.1.10", "10.0.0.0/16").
  - `AccessTarget::Account(String)`: AccountId32 address string.
  - _Note: This job should ideally be restricted to admin callers._
- **`PAY_FOR_ACCESS_JOB_ID` (1):** Grant temporary access to the _caller_.
  - **Input Type:** `PayForAccessInput { duration_secs: u64 }`
  - _Note: Payment verification logic needs to be implemented within the job handler based on your specific requirements (e.g., checking token transfers, EVM events)._
- **`REGISTER_WEBHOOK_JOB_ID` (2):** Register a new webhook URL.
  - **Input Type:** `RegisterWebhookInput { url: String }`
  - URL must use `http` or `https` scheme.

Refer to the types defined in `blockchain-rpc-lib/src/jobs/` for exact input structures and serialization details.

## 📜 License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
