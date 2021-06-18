// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use crate::{
    utils::{decode, encode},
    Actions, Directions, FwRule, Protocols,
};
use libc::{c_char, c_long};

#[allow(non_camel_case_types)]
#[derive(Clone)]
#[repr(C)]
pub(crate) struct fw_rule_impl {
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
