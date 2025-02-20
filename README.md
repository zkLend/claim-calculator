# claim-calculator

A command line utility for deterministically generating user claim data in relation to the [zkLend security incident](https://zklend.medium.com/zklend-security-incident-post-mortem-27d9abaf66f6).

While more efficient indexing solutions exist, this tool has been designed to have as few dependencies as possible in order to make it easier to verify snapshot data. The tool only requires a Starknet RPC endpoint (spec version v0.7.1) to run.

The zkLend market contract was [upgraded](https://voyager.online/tx/0x057a07cb48fd0f7af8330dcfcfb0d32e180cb099a1100a3205a77bf4818902fe) on Starknet mainnet block `1144392`, disallowing any lending activities. However, ZTokens remains transferrable as of this writing. The team will further upgrade ZToken contracts on a future block `xxxxxxx` (available after halting). Therefore, in order to attribute losses to account addresses, snapshot data are sourced from two different blocks:

- block `1144392`:
  - asset prices
  - asset balances
  - market lending/borrowing accumulators
  - user raw debt balances
- block `xxxxxxx` (to be determined):
  - user raw collateral balances

Before running the tool, set the `STARKNET_RPC` environment variable to the URL of a Starknet JSON-RPC endpoint (v0.7.1).

> [!NOTE]
>
> Since the tool makes a large number of requests, it's recommended that a local Starknet client (e.g. [`pathfinder`](https://github.com/eqlabs/pathfinder)) is used.

To run the tool:

```
cargo run --release
```

> [!WARNING]
>
> Currently the tool makes some assumptions during the calculation process, specifically regarding ZToken transfers post market halt and pool token liquidation prices. Therefore, the claim data generated are preliminary and must be treated as such.
>
> This is also why a copy of the deterministically generated data is currently _not_ included in this repository. Once the assumptions are replaced with actual data, the final claim data will be published here for verification.
