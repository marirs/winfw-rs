// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use crate::{fw_rule_impl, FwRule};
use libc::c_char;

pub(crate) fn decode(c: [c_char; 1024]) -> &'static str {
    let a_ref = &c;
    let a_ptr = a_ref as *const i8;
    let c_str: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(a_ptr) };
    c_str.to_str().unwrap()
}

pub(crate) fn encode(s: &str, c: &mut [c_char; 1024]) {
    if !s.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                s.as_bytes().as_ptr() as *const i8,
                c.as_mut_ptr(),
                s.as_bytes().len(),
            );
        }
    }
}

pub(crate) fn decode_vecs(c: Vec<fw_rule_impl>) -> Vec<FwRule> {
    let mut res = Vec::<FwRule>::new();
    for rule in c.iter() {
        res.push(rule.into());
    }
    res
}
