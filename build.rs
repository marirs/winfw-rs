// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.

use cc;

#[cfg(not(windows))]
fn main() {
    eprintln!("It is a Windows only crate.");
}

#[cfg(windows)]
fn main() {
    // Search of altcomcli.h file if possible.
    let mut incpath = String::new();
    for entry in glob::glob("C:/Program Files/Microsoft Visual Studio/**/atlcomcli.h")
        .expect("Failed to read glob pattern")
    {
        match entry {
            Ok(p) => {
                println!("Found {:?}", p);
                incpath.push_str(&format!(";{}", p.parent().unwrap().display()));
            }
            Err(e) => println!("{:?}", e),
        }
    }
    std::env::set_var("INCLUDE", incpath);
    cc::Build::new()
        .cpp(true)
        .file("src/bindings.cpp")
        .compile("fwb");
}
