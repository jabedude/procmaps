# Rust procmaps - retrieve process memory maps

A library for retrieving information about memory mappings for Unix processes.

To use, add this line to your Cargo.toml:

```toml
[dependencies]
procmaps = "0.4.1"
```
## Example
```rust
use procmaps::Mappings;

let mappings = Mappings::from_pid(pid).unwrap();
for mapping in mappings.iter() {
    if mapping.perms.executable {
        println!("Region: {:x} - {:x} Size: {}", mapping.base, mapping.ceiling, mapping.size_of_mapping());
    }
}
```
