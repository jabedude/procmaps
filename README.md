# Rust procmaps - retrieve process memory maps

A library for retrieving information about memory mappings for Unix processes.

To use, add this line to your Cargo.toml:

```toml
[dependencies]
procmaps = "0.4.0"
```
## Example
```rust
use procmaps::maps;

let m = maps(pid).unwrap();
for mapping in m {
    if mapping.perms.executable {
        println!("Region: {:x} - {:x} Size: {}", mapping.base, mapping.ceiling, mapping.size_of_mapping());
    }
}
```
