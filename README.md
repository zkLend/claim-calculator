# claim-calculator

> [!IMPORTANT]
>
> **You agree to the [zkLend Recovery Pool's terms and conditions](https://recovery.zklend.com/terms)** by interacting with the zkLend recovery contract on Starknet mainnet using proofs:
>
> - generated from this tool; or
> - provided herein.

A command line utility for deterministically generating user claim data in relation to the [zkLend security incident](https://zklend.medium.com/zklend-security-incident-post-mortem-27d9abaf66f6).

While more efficient indexing solutions exist, this tool has been designed to have as few dependencies as possible in order to make it easier to verify snapshot data. The tool only requires a Starknet RPC endpoint (spec version v0.7.1) to run.

The zkLend market contract was [upgraded](https://voyager.online/tx/0x057a07cb48fd0f7af8330dcfcfb0d32e180cb099a1100a3205a77bf4818902fe) on Starknet mainnet block `1144392`, disallowing any lending activities. However, ZTokens remained transferrable until block `1178488` when all contracts were further [upgraded](https://voyager.online/tx/0x020302acc52ee17f18d67115c776bbecd4baaf1baee35b243694cf6801c43ad5) to halt all operations. Therefore, in order to attribute losses to account addresses, snapshot data are sourced from two different blocks:

- block `1144392`:
  - asset prices
  - asset balances
  - market lending/borrowing accumulators
  - user raw debt balances
- block `1178488`:
  - user raw collateral balances

Before running the tool, set the `STARKNET_RPC` environment variable to the URL of a Starknet JSON-RPC endpoint (v0.7.1).

> [!NOTE]
>
> Since the tool makes a large number of requests, it's recommended that a local Starknet client (e.g. [`pathfinder`](https://github.com/eqlabs/pathfinder)) is used.

To run the tool:

```
cargo run --release
```

The command generates a Merkle tree with root `0x01cb091ca4e04a7d5864b59bef789fb7aba2752eef68686537102cd1901e0b10`. A generated `proofs.json` file contains full proofs for each entry in the tree. The result can be verified by re-running the tool as the whole generation process is deterministic.

> [!NOTE]
>
> In order to get around the GitHub file size limit of 100MB without resorting to LFS, the `proofs.json` file committed into this repository has been compressed into 2 formats:
>
> - [`proofs.zip`](./proofs.zip): use this format if you're using Windows, or other systems that do not support the `tar` or `gzip` utilities.
> - [`proofs.tar.gz`](./proofs.tar.gz): use this format if you're using Linux or macOS.
>
> Decompressing and extracting these 2 files shall yield the exact same `proofs.json` file with a SHA256 checksum of `270e52275a1f8090ef2bd11538bb5fbee094c556eab9ff027f7c62de6affce1c`.
