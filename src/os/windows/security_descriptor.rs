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


impl SecurityAttributes {
    pub fn any_user(&self) -> Self {
        Self {
            n_length: 0,
            attributes: Some("Everyone".to_string()),
            inherit_handle: 0,
        }
    }

}

impl SecurityAttributes {
    pub fn empty() -> SecurityAttributes {
        unsafe { std::mem::zeroed() }
    }
}

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