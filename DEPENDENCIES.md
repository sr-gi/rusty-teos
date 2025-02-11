# Dependencies

`rust-teos` has the following system-wide dependencies:

- `rust`
- `bitcoind`

### Minimum Supported Rust Version (MSRV)
Refer to [toolchain](./rust-toolchain.toml)

### Installing Rust
Refer to [rust-lang.org](https://www.rust-lang.org/tools/install).

### Installing bitcoind

`rust-teos` runs on top of a Bitcoin Core node. Other underlying Bitcoin nodes are not supported at the moment. 

You can get Bitcoin Core from [bitcoincore.org](https://bitcoincore.org/en/download/).

Bitcoin needs to be running with the following options enabled:

- `server` to run rpc commands

Here's an example of a `bitcoin.conf` you can use for mainnet. **DO NOT USE THE PROVIDED RPC USER AND PASSWORD.**

```
# [rpc]
server=1
rpcuser=user
rpcpassword=passwd
rpcservertimeout=600

# [others]
daemon=1
debug=1
maxtxfee=1
```
