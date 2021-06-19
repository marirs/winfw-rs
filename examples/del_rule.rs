use winfw::del_fw_rule;

fn main() {
    // delete rule
    match del_fw_rule(&"TEST_INTERFACE_RULE".to_string()) {
        Err(e) => println!("Error: {}", e),
        Ok(()) => println!("Success"),
    }
}
