# PCAPNG

spec: https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html

## Build

This implementation uses the underlying linux system calls to perform file i/o and does not use rust based file i/o.

```rust
cargo build
```

## Testing

```rust
cargo test -- --nocapture
```

This tests the library features.
