use crate::os::windows::c_wrappers;
use crate::os::windows::LPVOID;
use winapi::ctypes::c_void;
use winapi::shared::sddl::SDDL_REVISION_1;
use winapi::shared::sddl::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use winapi::um::winnt::LPWSTR;
use crate::os::windows::DWORD;
use winapi::shared::sddl::ConvertSecurityDescriptorToStringSecurityDescriptorW;
use winapi::um::winnt::SECURITY_DESCRIPTOR_CONTROL;
use std::ptr;
use winapi::um::{
    handleapi::DuplicateHandle, minwinbase::SECURITY_ATTRIBUTES, processthreadsapi::GetCurrentProcess,
    winnt::{DUPLICATE_SAME_ACCESS, ACL},
    accctrl::{EXPLICIT_ACCESS_W, SET_ACCESS, NO_INHERITANCE, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_IS_SID},
    securitybaseapi::{SetSecurityDescriptorDacl, InitializeSecurityDescriptor, CreateWellKnownSid},
    aclapi::SetEntriesInAclW,
    winnt::{SECURITY_DESCRIPTOR, PSID, PSECURITY_DESCRIPTOR,
            PACL, GENERIC_WRITE, SECURITY_DESCRIPTOR_MIN_LENGTH, GENERIC_READ,
            SECURITY_DESCRIPTOR_REVISION, FILE_GENERIC_EXECUTE,  WinBuiltinUsersSid}
};
use anyhow::anyhow;
use std::fmt::{self, Debug};
pub type SecurityDescriptorError<T> = Result<T, anyhow::Error>;

/*#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecurityAttributes {
    length: u32,
    descriptor: Option<SecurityDescriptor>,
    inherit_handle: i32,
}*/



#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecurityAttributes {
    pub n_length: u32,
    pub attributes: Option<String>,
    pub inherit_handle: i32,
}



impl Default for SecurityAttributes {
    fn default() -> Self {
        Self {
            n_length: 0,
            attributes: None,
            inherit_handle: 0,
        }
    }
}


// impl SecurityAttributes {
//     fn secure_descriptor(&self) -> SecurityDescriptor {
//         SecurityDescriptor(self.attributes.security_descriptor)
//     }
// }

// struct SecurityDescriptor {
//     ptr: PSECURITY_DESCRIPTOR
// }
//
impl SecurityDescriptor {
    // fn as_mut_ptr(&mut self) -> PSECURITY_DESCRIPTOR {
    //     self.ptr
    // }
    //
    // fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
    //     self.ptr as *const SECURITY_DESCRIPTOR
    // }
    //
    // fn get_mut(&mut self) -> &mut SECURITY_DESCRIPTOR {
    //     self.ptr
    // }
    //
    // fn group(&self) -> PACL {
    //     self.get_mu
    // }
    //


}

// impl Into<SECURITY_ATTRIBUTES> for SecurityAttributes {
//     fn into(self) -> SECURITY_ATTRIBUTES {
//         c_wrappers::obtain_secure_descriptor()
//     }
// }
impl SecurityAttributes {
    // pub fn get_descriptor(&self) -> SECURITY_ATTRIBUTES {
    //     self.clone().into()
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
    //}
    // pub fn any_user() -> Self {
    //     let mut sa = SecurityAttributes::empty();
    //
    //     sa.set_all_users();
    //
    //     sa
    // }
    pub fn any_user(&self) -> Self {
        let sd = SecurityDescriptor::any_user();

        Self {
            n_length: 0,
            attributes: Some(sd.to_string()),
            inherit_handle: 0,
        }
    }
    // pub fn from_sddl(sddl: &str) -> SecurityDescriptorError<SECURITY_DESCRIPTOR> {
    //     let sddl_wide: Vec<u16> = sddl.encode_utf16().collect();
    //     let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    //
    //     let result = unsafe {
    //         ConvertStringSecurityDescriptorToSecurityDescriptorW(
    //             sddl_wide.as_ptr(),
    //             SDDL_REVISION_1.into(),
    //             &mut security_descriptor,
    //             ptr::null_mut(), // Use null if you don't need the returned size
    //         )
    //     };
    //
    //     if result != 0 {
    //         Ok(security_descriptor)
    //     }
    //     Err(anyhow!("Error converting SDDL to security descriptor"))
    //
    // }

    fn as_sddl(sd: SECURITY_DESCRIPTOR) -> SecurityDescriptorError<String> {
        let mut sddl: LPWSTR = ptr::null_mut();
        let mut sddl_length: DWORD = 0;
        let p_sd: PSECURITY_DESCRIPTOR = &sd as *const _ as PSECURITY_DESCRIPTOR;
        let result = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                p_sd,
                SDDL_REVISION_1.into(),
                0, // Flags for specific components to convert. Use 0 for all.
                &mut sddl,
                &mut sddl_length,
            )
        };

        if result != 0 {
            let sddl_str = unsafe {
                let slice = std::slice::from_raw_parts(sddl as *const u16, sddl_length as usize);
                String::from_utf16_lossy(slice)
            };
            return Ok(sddl_str);
        }
        Err(anyhow!("Error converting security descriptor to SDDL"))
    }


}

impl SecurityAttributes {
    pub fn empty() -> SecurityAttributes {
        unsafe { std::mem::zeroed() }
    }
    // pub fn with_descriptor(descriptor: SecurityDescriptor) -> Self {
    //     Self {
    //
    //         length: 0,
    //         descriptor: Some(descriptor),
    //         inherit_handle: 0,
    //     }
    // }
}

// impl Into<SecurityAttributes> for SecurityDescriptor {
//     fn into(self) -> SecurityAttributes {
//         SecurityAttributes::with_descriptor(self)
//     }
// }

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SecurityDescriptor {
    revision: u8,
    sbz1: u8,
    control: SECURITY_DESCRIPTOR_CONTROL,
    owner: PSID,
    group: PSID,
    sacl: PACL,
    dacl: PACL,
}


pub type PISECURITY_DESCRIPTOR = *mut SECURITY_DESCRIPTOR;
impl Clone for SecurityDescriptor {
    fn clone(&self) -> Self {
        Self {
            revision: self.revision,
            sbz1: self.sbz1,
            control: self.control,
            owner: self.owner,
            group: self.group,
            sacl: self.sacl,
            dacl: self.dacl,
        }
    }
}
impl SecurityDescriptor {
    pub fn to_string(self) -> String {
        match SecurityAttributes::as_sddl(self.into()) {
            Ok(sddl) => {
                sddl
            }
            Err(_) => "".to_string(),
        }
    }

    pub fn any_user() -> Self {
        Self {
            revision: SECURITY_DESCRIPTOR_REVISION as u8,
            sbz1: 0,
            control: winapi::um::winnt::SE_DACL_PRESENT,
            owner: ptr::null_mut(),
            group: ptr::null_mut(),
            sacl: ptr::null_mut(),
            dacl: ptr::null_mut(),
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
impl Into<*mut c_void> for &SecurityDescriptor {
    fn into(self) -> *mut c_void {
        // Aquí puedes convertir tu SecurityDescriptor en un puntero crudo como sea necesario
        self as *const _ as *mut _
    }
}

//
//
// //        if let Some(descriptor) = self.security_attributes.clone(){
// //
// // SecurityAttributes
// //
// // -- Raw FFI --
// // as_ptr() -> PCSECURITY_ATTRIBUTES (*const SECURITY_ATTRIBUTES)
// // as_mut_ptr() -> PSECURITY_ATTRIBUTES (*mut SECURITY_ATTRIBUTES)
// //
// // - Rust refs
// // get() -> &SECURITY_ATTRIBUTES
// // get_mut() -> &mut SECURITY_ATTRIBUTES
// //
// // - High Level -
// //
// // as_user_X(&User) -> SecurityDescriptor
// // group(&self) -> Group // struct Group(PSID)
// //
// // SADDL
// // to_saddl() ->
// // into() -> SecurityAttributes -> SADDL String("S-12341234/;;1234;12412;341;234;1234")
// // as_saddl() -> String {
// // as_saddl() -> Saddl { (struct Saddl(String)
//
// // SecurityAttributes::from_saddl(saddl);
// //
// // saddl.as_security_attributes(&self) -> SecurityAttributes {
// //       SecurityAttributes::from_saddl(saddl);
// // }
// //
// //
//
// //
// // let mut security_attributes = SecurityAttributes::empty();
// //
// // SecurityAttributes (self.attributes = std::mem::zeroed(); )
// //
// // security_attributes.set_all_users();
// //
// //
// //
//
// pub fn set_all_users(&mut self) -> Result<SECURITY_ATTRIBUTES>{
//     let mut security_descriptor: Vec<u8> = vec![0; SECURITY_DESCRIPTOR_MIN_LENGTH];
//     let p_security_descriptor: PSECURITY_DESCRIPTOR = security_descriptor.as_mut_ptr() as PSECURITY_DESCRIPTOR;
//
//
//     // SecurityAttributes -> SecurityDescriptor(PSECURITY_DESCRIPTOR) -> &mut SecurityDescriptor,
//     let mut sd = self.security_descriptor();
//
//     sd.initialize(SECURITY_DESCRIPTOR_REVISION);
//
//     let sid = Sid::create(WinBuiltinUsersSid, None, sid)
//
//     struct ExplicitAccessBuilder {
//         permissions: DWORD
//         access_mode:
//     }
//     let ea = ExplicitAccess::with_trustee(sid, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP)
//         .permissions(GENERIC_READ | GENERIC_WRITE | FILE_GENERIC_EXECUTE)
//         .access_mode(SET_ACCESS)
//         .inheritance(NO_INHERITANCE)
//         .build();
//
//     sd.set_sid()?;
//
//     //
//     // SecurityResult
//     //
//     // fn set_sid(kind: WellKnownSidType, domain: Option<SidDomain>, sid: Option<Sid>) -> SecurityResult<()> {
//     //
//     // ffi::create_well_known_sid() -> FffResult<>
//     // ffi::create_well_known_sid(WinBuiltinUsersSid, ptr::null_mut(), sid_buffer.as_mut_ptr() as PSID, &mut sid_size)?.
//     //          .context();
//     //
//     // if CreateWellKnownSid(WinBuiltinUsersSid, ptr::null_mut(), sid_buffer.as_mut_ptr() as PSID, &mut sid_size) == 0 {
//     //    return Err(SecurityError::CreateWellKnownSidError);
//     // }
//     //
//     //     eprintln!("Error to create SID: {}", std::io::Error::last_os_error());
//     //     return sa;
//     // }
//     //     struct Sid {
//     //        sid: Vec<u8>,
//     //     }
//     //
//
//     //
//     // self.attributes.security_descriptor(
//     //
//     // SecurityAttributes -> self.attributes
//     // fn security_descriptor(&mut self) -> SecurityDescriptor
//     //
//     // SecurityDescriptor != SECURITY_DESCRIPTOR, SecurityDescriptor(PSECURITY_DESCRIPTOR)
//     //
//     //
//     //
//     unsafe {
//         if InitializeSecurityDescriptor(self.attributes.security_descriptor().as_mut_ptr()p_security_descriptor, SECURITY_DESCRIPTOR_REVISION) == 0{
//             eprintln!("Errpr to initialize security descriptor: {}", std::io::Error::last_os_error());
//             return sa;
//         }
//         // create SID for all users
//         let mut sid_buffer: Vec<u8> = vec![0; 68]; // max size for SID
//         let mut sid_size: u32 = sid_buffer.len() as u32;
//         if CreateWellKnownSid(WinBuiltinUsersSid, ptr::null_mut(), sid_buffer.as_mut_ptr() as PSID, &mut sid_size) == 0 {
//             eprintln!("Error to create SID: {}", std::io::Error::last_os_error());
//             return sa;
//         }
//
//
//
//         let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
//         ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | FILE_GENERIC_EXECUTE;
//         ea.grfAccessMode = SET_ACCESS;
//         ea.grfInheritance = NO_INHERITANCE;
//         ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
//         ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
//         ea.Trustee.ptstrName = sid_buffer.as_ptr() as *mut u16;
//
//         let acl_size: u32 = 0;
//         let mut acl_buffer: Vec<u8> = vec![0; acl_size as usize];
//         let p_acl: PACL = acl_buffer.as_mut_ptr() as PACL;
//         let mut acl: PACL = ptr::null_mut();
//         if SetEntriesInAclW(1,
//                             &mut ea,
//                             p_acl,
//                             &mut acl) == 0{
//             eprintln!("SetEntriesInAclW failed: {}", std::io::Error::last_os_error());
//             return sa;
//         }
//
//         if SetSecurityDescriptorDacl(p_security_descriptor, 1, p_acl, 0) == 0{
//             eprintln!("SetSecurityDescriptorDacl failed: {}", std::io::Error::last_os_error());
//             return sa;
//         }
//
//         sa.lpSecurityDescriptor = p_security_descriptor;
//
//         sa
//     }
// }