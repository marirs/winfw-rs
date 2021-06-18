// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
#[repr(transparent)]
pub struct Error(pub libc::c_ulong);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:#08x}", self.0)
    }
}
