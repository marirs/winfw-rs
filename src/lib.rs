// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use libc::{c_char, c_long, c_ulong};
use std::fmt::{self, Display, Formatter};
use std::vec::Vec;

mod utils;
use self::utils::{decode_vecs, encode};

mod cfw;
use cfw::fw_rule_impl;

mod consts;
pub use self::consts::{Actions, Directions, Protocols};

mod error;
pub use self::error::Error;

#[derive(Default, Clone)]
#[repr(C)]
pub struct FwRule {
    pub name: String,
    pub description: String,
    pub app_name: String,
    pub service_name: String,
    pub protocol: Protocols,
    pub icmp_type: String,
    pub local_ports: String,
    pub remote_ports: String,
    pub local_adresses: String,
    pub remote_addresses: String,
    pub profile1: String,
    pub profile2: String,
    pub profile3: String,
    pub direction: Directions,
    pub action: Actions,
    pub interface_types: String,
    pub interfaces: String,
    pub enabled: bool,
    pub grouping: String,
    pub edge_traversal: bool,
}

impl Display for FwRule {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "name: {}\ndescription: {}\napplication name: {}\nservice name: {}\nprotocol: {}\nicmp type: {}\nlocal ports: {}\nremote ports: {}\nlocal address: {}\nremote address: {}\nprofiles: {} {} {}\ndirection: {}\naction: {}\ninterfaces types: {}\ninterfaces: {}\nenabled: {}\ngrouping: {}\nedge traversal: {}\n---",
        self.name,
        self.description,
        self.app_name,
        self.service_name,
        self.protocol,
        self.icmp_type,
        self.local_ports,
        self.remote_ports,
        self.local_adresses,
        self.remote_addresses,
        self.profile1,
        self.profile2,
        self.profile3,
        self.direction,
        self.action,
        self.interfaces,
        self.interface_types,
        self.enabled,
        self.grouping,
        self.edge_traversal)
    }
}

extern "C" {
    fn getFWRules(rules: &*mut fw_rule_impl, size: *mut c_long) -> c_ulong;
    fn newFWRule(rule: &fw_rule_impl) -> c_ulong;
    fn delFWRule(rule: *const c_char) -> c_ulong;
}

#[no_mangle]
pub fn get_fw_rules() -> Result<Vec<FwRule>, Error> {
    //! Gets all the firewal rules configured.
    //!
    //! ## Example usage
    //! ```rust
    //! use winfw::get_fw_rules;
    //!
    //! let rules = get_fw_rules();
    //! match rules {
    //!     Err(_) => assert!(false),
    //!     Ok(_) => {
    //!         assert!(true)
    //!    }
    //! }
    //! ```
    let mut required_size = 0;
    let rules: *mut fw_rule_impl = std::ptr::null_mut();
    let res = unsafe { getFWRules(&rules, &mut required_size) };
    if res != 0 {
        return Err(Error(res));
    }
    let fw_rules_slice = unsafe { std::slice::from_raw_parts_mut(rules, required_size as usize) };
    Ok(decode_vecs(fw_rules_slice.to_vec()))
}

#[no_mangle]
pub fn new_fw_rule(rule: &FwRule) -> Result<(), Error> {
    //! Add and configure a new firewall rule.
    //!
    //! ## Example usage
    //! ```ignore
    //! use winfw::{new_fw_rule, Actions, FwRule, Protocols};
    //!
    //! let mut new_rule = FwRule::default();
    //! new_rule.name = "TEST_INTERFACE_RULE".to_string();
    //! new_rule.description = "Allow incoming network traffic over port 2400 coming from LAN interface type".to_string();
    //! new_rule.grouping = "Test Rule Group".to_string();
    //! new_rule.grouping = "Test Rule Group".to_string();
    //! new_rule.local_ports = "2400-2450".to_string();
    //! new_rule.interface_types = "LAN".to_string();
    //! new_rule.protocol = Protocols::Tcp;
    //! new_rule.action = Actions::Allow;
    //! new_rule.enabled = true;
    //! match new_fw_rule(&new_rule) {
    //!     Err(_) => assert!(false),
    //!     Ok(()) => assert!(true),
    //! }
    //! ```
    let fw_rule: fw_rule_impl = rule.into();
    let res = unsafe { newFWRule(&fw_rule) };
    if res != 0 {
        return Err(Error(res));
    }
    Ok(())
}

#[no_mangle]
pub fn del_fw_rule(name: &str) -> Result<(), Error> {
    //! Deletes an existing firewall rule.
    //!
    //! ## Example usage
    //! ```ignore
    //! use winfw::del_fw_rule;
    //!
    //! match del_fw_rule(&"TEST_INTERFACE_RULE".to_string()) {
    //!     Err(_) => assert!(false),
    //!     Ok(()) => assert!(true),
    //! }
    //! ```
    let mut s: [c_char; 1024] = [0; 1024];
    encode(name, &mut s);
    let res = unsafe { delFWRule(s.as_ptr()) };
    if res != 0 {
        return Err(Error(res));
    }
    Ok(())
}

#[no_mangle]
pub fn disable_fw_rule(name: &str) -> Result<(), Error> {
    //! Disables an existing firewall rule.
    //!
    //! ## Example usage
    //! ```ignore
    //! use winfw::disable_fw_rule;
    //!
    //! match disable_fw_rule(&"TEST_INTERFACE_RULE".to_string()) {
    //!     Err(_) => assert!(false),
    //!     Ok(()) =>  assert!(true),
    //! }
    //! ```
    let rules = get_fw_rules();
    match rules {
        Err(rules) => Err(rules),
        Ok(rules) => {
            for rule in rules.iter() {
                if rule.name.eq(name) {
                    let mut r = rule.clone();
                    r.enabled = false;
                    return new_fw_rule(&r);
                }
            }
            Err(Error(32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_fw_rules() {
        let rules = get_fw_rules();
        match rules {
            Err(_) => assert!(false),
            Ok(_) => {
                assert!(true)
            }
        }
    }
}
