use winfw::disable_fw_rule;

fn main() {
    // disable rule
    match disable_fw_rule(&"TEST_INTERFACE_RULE".to_string()) {
        Err(e) => println!("Error: {}", e),
        Ok(()) => println!("Success"),
    }
}
