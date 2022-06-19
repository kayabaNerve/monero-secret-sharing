# Monero Secret Sharing

A tool to generate a Monero wallet distributed across the specified amount of
shares with the specified amount required to recover the wallet as a whole. This
is a proof of concept which only supports generating testnet addresses. This is
not a multisig tool, yet rather a way to enable backing up your wallet among
trusted parties.

The created JSON files do contain the wallet's address and view key. At this
time, these must be manually removed for all parties you do not want to be able
to watch over the wallet.

This uses the FROST key generation protocol to create a key, then writes shares
to JSON files under the specified path which can later be re-combined.

For instructions on how to use it, pass `--help` when running it.
