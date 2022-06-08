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
            println!("Total rules: {}", rules.len());
        }
    }
}
