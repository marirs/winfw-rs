use winfw::enable_fw_rule;

fn main() {
    // enable rule
    match enable_fw_rule(&"TEST_INTERFACE_RULE".to_string()) {
        Err(e) => println!("Error: {}", e),
        Ok(()) => println!("Success"),
    }
}
