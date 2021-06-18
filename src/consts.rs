// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use std::fmt::{self, Display, Formatter};
use libc::c_long;

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
