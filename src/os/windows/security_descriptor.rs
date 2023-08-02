use crate::os::windows::c_wrappers;
use winapi::um::minwinbase::{SECURITY_ATTRIBUTES};
use winapi::um::winnt::SECURITY_DESCRIPTOR;

///
///      let mut security_descriptor = winapi::um::winnt::SECURITY_DESCRIPTOR {
//                 Revision: 1,
//                 Sbz1: 0,
//                 Control: 4,
//                 Owner: std::ptr::null_mut(),
//                 Group: std::ptr::null_mut(),
//                 Sacl: std::ptr::null_mut(),
//                 Dacl: std::ptr::null_mut(),
//             };
//             let mut security_attributes = winapi::um::minwinbase::SECURITY_ATTRIBUTES {
//                 nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32,
//                 lpSecurityDescriptor: &mut security_descriptor as *mut winapi::um::winnt::SECURITY_DESCRIPTOR as *mut std::ffi::c_void,
//                 bInheritHandle: 0, // 0 si no deseas heredar el descriptor
//             };


#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecurityAttributes {
    inherit_handle: i32,
    descriptor: Option<SecurityDescriptor>,
}

impl Into<SECURITY_ATTRIBUTES> for SecurityAttributes {
    fn into(self) -> SECURITY_ATTRIBUTES {

        let mut sa = c_wrappers::init_security_attributes();
        sa.bInheritHandle = self.inherit_handle;
        if let Some(descriptor) = self.descriptor.clone() {
            let mut security_descriptor: SECURITY_DESCRIPTOR = descriptor.into();
            sa.lpSecurityDescriptor = &mut security_descriptor as *mut winapi::um::winnt::SECURITY_DESCRIPTOR as *mut std::ffi::c_void;
        }
        sa
    }
}

impl Default for SecurityAttributes {
    fn default() -> Self {
        SecurityAttributes {
            inherit_handle: 0,
            descriptor: None
        }
    }
}


impl SecurityAttributes {

    pub fn with_descriptor(descriptor: SecurityDescriptor) -> Self {
        Self {
            inherit_handle: 0,
            descriptor: Some(descriptor),
        }
    }
}

impl Into<SecurityAttributes> for SecurityDescriptor {
    fn into(self) -> SecurityAttributes {
        SecurityAttributes::with_descriptor(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecurityDescriptor {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: usize,
    group: usize,
    g_group: usize,
    sacl: usize,
    dacl: usize,
}

impl Into<SECURITY_DESCRIPTOR>  for SecurityDescriptor {
    fn into(self) -> SECURITY_DESCRIPTOR {
        winapi::um::winnt::SECURITY_DESCRIPTOR {
            Revision: self.revision,
            Sbz1: self.sbz1,
            Control: self.control,

            Owner: if self.owner == 0 {
                std::ptr::null_mut()
            } else {
                self.owner as *mut _
            } ,
            Group: if self.group == 0{
                std::ptr::null_mut()
            } else {
                self.group as *mut _
            },
            Sacl:if self.sacl == 0{
                std::ptr::null_mut()
            } else {
                self.sacl as *mut _
            },
            Dacl: if self.dacl == 0{
                std::ptr::null_mut()
            } else {
                self.dacl as *mut _
            },
        }
    }
}

impl SecurityDescriptor {
    pub fn any() -> Self {
        Self {
            revision: 1,
            sbz1: 0,
            control: 4,
            owner: 0,
            group: 0,
            g_group: 0,
            sacl: 0,
            dacl: 0,
        }
    }
}