use crate::os::windows::c_wrappers;
use crate::os::windows::LPVOID;
use winapi::ctypes::c_void;
use winapi::um::{
    minwinbase::{SECURITY_ATTRIBUTES},
    winnt::{SECURITY_DESCRIPTOR, ACL}
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecurityAttributes {
    length: u32,
    descriptor: Option<SecurityDescriptor>,
    inherit_handle: i32,
}

impl Into<SECURITY_ATTRIBUTES> for SecurityAttributes {
    fn into(self) -> SECURITY_ATTRIBUTES {
        let mut sa = c_wrappers::init_security_attributes();
        sa.bInheritHandle = self.inherit_handle;

        if let Some(security_descriptor) = &self.descriptor {
        let mut descriptor: Box<SECURITY_DESCRIPTOR> = Box::new(security_descriptor.clone().into());
          sa.lpSecurityDescriptor = descriptor.as_mut() as *mut _ as *mut std::ffi::c_void;
        } else {
            sa.lpSecurityDescriptor = std::ptr::null_mut();
        }

        sa
    }
}
impl SecurityAttributes {
    pub fn get_descriptor(&self) -> SECURITY_ATTRIBUTES {
        self.clone().into()
    //     //TODO call crate::c_wrappers::obtain_secure_descriptor()
    //     let mut security_descriptor: Box<SECURITY_DESCRIPTOR> = Box::new(SECURITY_DESCRIPTOR {
    //         Revision: 1,
    //         Sbz1: 0,
    //         Control: 4,
    //         Owner: std::ptr::null_mut(),
    //         Group: std::ptr::null_mut(),
    //         Sacl: std::ptr::null_mut(),
    //         Dacl: std::ptr::null_mut(),
    //     });
    //
    //     let mut security_attributes: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
    //         nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
    //         lpSecurityDescriptor: security_descriptor.as_mut() as *mut _ as *mut std::ffi::c_void,
    //         bInheritHandle: 0, // 0 si no deseas heredar el descriptor
    //     };
    //
    //     security_attributes
    }
    pub fn any() -> Self {
        Self {
            length: 0,
            descriptor: Some(SecurityDescriptor::any()),
            inherit_handle: 0,
        }
    }
}

impl Default for SecurityAttributes {
    fn default() -> Self {
        Self {
            length: 0,
            descriptor: None,
            inherit_handle: 0,
            }
        }
    }

impl SecurityAttributes {

    pub fn with_descriptor(descriptor: SecurityDescriptor) -> Self {
        Self {
            length: 0,
            descriptor: Some(descriptor),
            inherit_handle: 0,
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
    owner: *mut c_void,
    group: *mut c_void,
    sacl: *mut c_void,
    dacl: *mut c_void,
}

impl SecurityDescriptor {
    pub fn any() -> Self {
        Self {
            revision: 1,
            sbz1: 0,
            control: 4,
            owner: std::ptr::null_mut(),
            group: std::ptr::null_mut(),
            sacl: std::ptr::null_mut(),
            dacl: std::ptr::null_mut(),
        }
    }
}


impl Into<SECURITY_DESCRIPTOR> for SecurityDescriptor {
    fn into(self) -> SECURITY_DESCRIPTOR {
        SECURITY_DESCRIPTOR {
            Revision: self.revision,
            Sbz1: self.sbz1,
            Control: self.control,
            // TODO: Add owner, group, sacl, dacl pointers
            Owner: self.owner,
            Group: self.group,
            Sacl: self.sacl as *mut ACL,
            Dacl: self.dacl as *mut ACL,
        }
    }
}