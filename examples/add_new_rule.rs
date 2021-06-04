use winfw::{new_fw_rule, Actions, FwRule, Protocols};

fn main() {
    // add fw rule
    let mut new_rule = FwRule::default();
    new_rule.name = "PER_INTERFACETYPE_RULE".to_string();
    new_rule.description =
        "Allow incoming network traffic over port 2400 coming from LAN interface type".to_string();
    new_rule.grouping = "Sample Rule Group".to_string();
    new_rule.grouping = "Sample Rule Group".to_string();
    new_rule.local_ports = "2400-2450".to_string();
    new_rule.interface_types = "LAN".to_string();
    new_rule.protocol = Protocols::Tcp;
    new_rule.action = Actions::Allow;
    new_rule.enabled = true;
    match new_fw_rule(&new_rule) {
        Err(e) => println!("Error: {}", e),
        Ok(()) => println!("Success"),
    }
}
