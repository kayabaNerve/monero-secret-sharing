# Monero Secret Sharing

A tool to generate a Monero wallet distributed across the specified amount of
shares with the specified amount required to recover the wallet as a whole. This
is a proof of concept which only supports generating testnet addresses. This is
not a multisig tool, yet rather a way to enable backing up your wallet among
trusted parties.

This uses the FROST key generation protocol to create a key, then writes shares
to JSON files under the specified path which can later be re-combined.

For instructions on how to use it, pass `--help` when running it.
