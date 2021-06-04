// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
extern crate cc;

fn main() {
    cc::Build::new()
        .cpp(true)
        .file("src/bindings.cpp")
        .compile("fwb");
}
