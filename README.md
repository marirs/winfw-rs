Windows Firewall
==================

Bindings for Windows Firewall, with clean & simple API for use with Rust.  
  
This crate can perform the following:
- Enumerate the Windows firewall rules
- Add/Create a new Windows firewall rule
- Delete an existing Windows firewall rule
- Disable an existing Windows firewall rule

### Usage

Cargo.toml:
```toml
[target.'cfg(windows)'.dependencies]
winfw = { git = "https://github.com/marirs/winfw-rs", branch = "master" }
```

main.rs:
```rust
use winfw::get_fw_rules;

fn main() {
    // enumerating fw rules
    let rules = get_fw_rules();
    match rules {
        Err(rules) => println!("Error: {}", rules),
        Ok(rules) => {
            for rule in rules.iter() {
                println!("{}", rule);
            }
        }
    }
}
```

### running the example
- Show/list all configured firewall rules
```bash
cargo run --example list_all_rules
```

- Add a new firewall rule
```bash
cargo run --example add_new_rule
```

- Delete a firewall rule
```bash
cargo run --example del_rule
```

- Disable a firewall rule
```bash
cargo run --example disable_rule
```

### Requirements
- Rust 1.50+
- VS 2019 community edition

---
License: MIT/Apache 2.0
