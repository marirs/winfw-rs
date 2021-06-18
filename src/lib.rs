// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use std::fmt::{self, Debug, Display, Formatter};
extern crate libc;
use libc::{c_char, c_long, c_ulong};
use std::vec::Vec;

#[derive(Debug)]
#[repr(transparent)]
pub struct Error(libc::c_ulong);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:#08x}", self.0)
    }
}

#[derive(Clone)]
pub enum Protocols {
    Tcp,
    Udp,
    Any,
}

impl From<c_long> for Protocols {
    fn from(w: c_long) -> Protocols {
        match w {
            0x00000006 => Protocols::Tcp,
            0x00000011 => Protocols::Udp,
            _ => Protocols::Any,
        }
    }
}

impl Default for Protocols {
    fn default() -> Self {
        Protocols::Any
    }
}

impl Display for Protocols {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Protocols::Tcp => write!(f, "TCP"),
            Protocols::Udp => write!(f, "UDP"),
            Protocols::Any => write!(f, "Any"),
        }
    }
}

#[derive(Clone)]
pub enum Directions {
    In,
    Out,
    Any,
}

impl From<c_long> for Directions {
    fn from(w: c_long) -> Directions {
        match w {
            1 => Directions::In,
            2 => Directions::Out,
            _ => Directions::Any,
        }
    }
}

impl Default for Directions {
    fn default() -> Self {
        Directions::Any
    }
}
impl Display for Directions {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Directions::In => write!(f, "IN"),
            Directions::Out => write!(f, "OUT"),
            Directions::Any => write!(f, "Any"),
        }
    }
}

#[derive(Clone)]
pub enum Actions {
    Block,
    Allow,
}

impl From<c_long> for Actions {
    fn from(w: c_long) -> Actions {
        match w {
            0 => Actions::Block,
            _ => Actions::Allow,
        }
    }
}

impl Default for Actions {
    fn default() -> Self {
        Actions::Block
    }
}

impl Display for Actions {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Actions::Block => write!(f, "BLOCK"),
            Actions::Allow => write!(f, "ALLOW"),
        }
    }
}

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

#[derive(Clone)]
#[repr(C)]
struct fw_rule_impl {
    pub name: [c_char; 1024],
    pub description: [c_char; 1024],
    pub app_name: [c_char; 1024],
    pub service_name: [c_char; 1024],
    pub protocol: c_long,
    pub icmp_type: [c_char; 1024],
    pub local_ports: [c_char; 1024],
    pub remote_ports: [c_char; 1024],
    pub local_adresses: [c_char; 1024],
    pub remote_addresses: [c_char; 1024],
    pub profile1: [c_char; 1024],
    pub profile2: [c_char; 1024],
    pub profile3: [c_char; 1024],
    pub direction: c_long,
    pub action: c_long,
    pub interface_types: [c_char; 1024],
    pub interfaces: [c_char; 1024],
    pub enabled: c_long,
    pub grouping: [c_char; 1024],
    pub edge_traversal: c_long,
}

impl From<&fw_rule_impl> for FwRule {
    fn from(c: &fw_rule_impl) -> FwRule {
        FwRule {
            name: decode(c.name).to_string(),
            description: decode(c.description).to_string(),
            app_name: decode(c.app_name).to_string(),
            service_name: decode(c.service_name).to_string(),
            protocol: c.protocol.into(),
            icmp_type: decode(c.icmp_type).to_string(),
            local_ports: decode(c.local_ports).to_string(),
            remote_ports: decode(c.remote_ports).to_string(),
            local_adresses: decode(c.local_adresses).to_string(),
            remote_addresses: decode(c.remote_addresses).to_string(),
            profile1: decode(c.profile1).to_string(),
            profile2: decode(c.profile2).to_string(),
            profile3: decode(c.profile3).to_string(),
            direction: c.direction.into(),
            action: c.action.into(),
            interface_types: decode(c.interface_types).to_string(),
            interfaces: decode(c.interfaces).to_string(),
            enabled: !c.enabled == 0,
            grouping: decode(c.grouping).to_string(),
            edge_traversal: !c.edge_traversal == 0,
        }
    }
}

impl Default for fw_rule_impl {
    fn default() -> Self {
        fw_rule_impl {
            name: [0; 1024],
            description: [0; 1024],
            app_name: [0; 1024],
            service_name: [0; 1024],
            protocol: 0x00000100,
            icmp_type: [0; 1024],
            local_ports: [0; 1024],
            remote_ports: [0; 1024],
            local_adresses: [0; 1024],
            remote_addresses: [0; 1024],
            profile1: [0; 1024],
            profile2: [0; 1024],
            profile3: [0; 1024],
            direction: 0,
            action: 0,
            interface_types: [0; 1024],
            interfaces: [0; 1024],
            enabled: 0,
            grouping: [0; 1024],
            edge_traversal: 0,
        }
    }
}

impl From<&FwRule> for fw_rule_impl {
    fn from(c: &FwRule) -> fw_rule_impl {
        let mut res = fw_rule_impl::default();
        encode(&c.name, &mut res.name);
        encode(&c.description, &mut res.description);
        encode(&c.app_name, &mut res.app_name);
        encode(&c.service_name, &mut res.service_name);
        res.protocol = match c.protocol {
            Protocols::Tcp => 0x00000006,
            Protocols::Udp => 0x00000011,
            _ => 0x00000100,
        };
        encode(&c.icmp_type, &mut res.icmp_type);
        encode(&c.local_ports, &mut res.local_ports);
        encode(&c.remote_ports, &mut res.remote_ports);
        encode(&c.local_adresses, &mut res.local_adresses);
        encode(&c.remote_addresses, &mut res.remote_addresses);
        encode(&c.profile1, &mut res.profile1);
        encode(&c.profile2, &mut res.profile2);
        encode(&c.profile3, &mut res.profile3);
        res.direction = match c.direction {
            Directions::In => 1,
            Directions::Out => 2,
            _ => 0,
        };
        res.action = match c.action {
            Actions::Allow => 1,
            _ => 0,
        };
        encode(&c.interface_types, &mut res.interface_types);
        encode(&c.interfaces, &mut res.interfaces);
        res.enabled = match c.enabled {
            true => 1,
            _ => 0,
        };
        encode(&c.grouping, &mut res.grouping);
        res.edge_traversal = match c.edge_traversal {
            true => 1,
            _ => 0,
        };
        res
    }
}

fn decode(c: [c_char; 1024]) -> &'static str {
    let a_ref = &c;
    let a_ptr = a_ref as *const i8;
    let c_str: &std::ffi::CStr = unsafe { std::ffi::CStr::from_ptr(a_ptr) };
    c_str.to_str().unwrap()
}

fn encode(s: &str, c: &mut [c_char; 1024]) {
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

fn decode_vecs(c: Vec<fw_rule_impl>) -> Vec<FwRule> {
    let mut res = Vec::<FwRule>::new();
    for rule in c.iter() {
        res.push(rule.into());
    }
    res
}

impl Display for FwRule {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "name: {}\ndescription: {}\napplication name: {}\nservice name: {}\nprotocol: {}\nicmp type: {}\nlocal ports: {}\nremote ports: {}\nlocal address: {}\nremote address: {}\nprofiles: {} {} {}\ndirection: {}\naction: {}\ninterfaces types: {}\ninterfaces: {}\nenabled: {}\ngrouping: {}\nedge traversal: {}", 
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
    fn remFWRule(rule: *const c_char) -> c_ulong;
}

#[no_mangle]
pub fn get_fw_rules() -> Result<Vec<FwRule>, Error> {
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
    let fw_rule: fw_rule_impl = rule.into();
    let res = unsafe { newFWRule(&fw_rule) };
    if res != 0 {
        return Err(Error(res));
    }
    Ok(())
}

#[no_mangle]
pub fn del_fw_rule(name: &str) -> Result<(), Error> {
    let mut s: [c_char; 1024] = [0; 1024];
    encode(name, &mut s);
    let res = unsafe { remFWRule(s.as_ptr()) };
    if res != 0 {
        return Err(Error(res));
    }
    Ok(())
}

#[no_mangle]
pub fn disable_fw_rule(name: &str) -> Result<(), Error> {
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
