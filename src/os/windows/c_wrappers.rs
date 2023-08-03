use super::winprelude::*;
use std::{
    io,
    mem::{size_of, zeroed},
};
use std::ptr;
use winapi::um::{
    handleapi::DuplicateHandle, minwinbase::SECURITY_ATTRIBUTES, processthreadsapi::GetCurrentProcess,
    winnt::DUPLICATE_SAME_ACCESS,
    accctrl::{EXPLICIT_ACCESS_W, SET_ACCESS, NO_INHERITANCE, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_IS_SID},
    securitybaseapi::{SetSecurityDescriptorDacl, InitializeSecurityDescriptor, CreateWellKnownSid},
    aclapi::SetEntriesInAclW,
    winnt::{SECURITY_DESCRIPTOR, PSID, PSECURITY_DESCRIPTOR,
            PACL, GENERIC_WRITE, SECURITY_DESCRIPTOR_MIN_LENGTH, GENERIC_READ,
            SECURITY_DESCRIPTOR_REVISION, FILE_GENERIC_EXECUTE,  WinBuiltinUsersSid}
};

pub fn obtain_secure_descriptor() -> Option<SECURITY_ATTRIBUTES>{
    // configure security descriptor to allow access to all users
    let mut sa: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 0,
    };

    let mut security_descriptor: Vec<u8> = vec![0; SECURITY_DESCRIPTOR_MIN_LENGTH];
    let p_security_descriptor: PSECURITY_DESCRIPTOR = security_descriptor.as_mut_ptr() as PSECURITY_DESCRIPTOR;
    unsafe {
        if InitializeSecurityDescriptor(p_security_descriptor, SECURITY_DESCRIPTOR_REVISION) == 0{
            eprintln!("Errpr to initialize security descriptor: {}", std::io::Error::last_os_error());
            return None;
        }
        // create SID for all users
        let mut sid_buffer: Vec<u8> = vec![0; 68]; // max size for SID
        let mut sid_size: u32 = sid_buffer.len() as u32;
        if CreateWellKnownSid(WinBuiltinUsersSid, ptr::null_mut(), sid_buffer.as_mut_ptr() as PSID, &mut sid_size) == 0 {
            eprintln!("Error to create SID: {}", std::io::Error::last_os_error());
            return None;
        }

        let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
        ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE | FILE_GENERIC_EXECUTE;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = sid_buffer.as_ptr() as *mut u16;

        let acl_size: u32 = 0;
        let mut acl_buffer: Vec<u8> = vec![0; acl_size as usize];
        let p_acl: PACL = acl_buffer.as_mut_ptr() as PACL;
        let mut acl: PACL = ptr::null_mut();
        if SetEntriesInAclW(1,
                            &mut ea,
                            p_acl,
                            &mut acl) == 0{
            eprintln!("SetEntriesInAclW failed: {}", std::io::Error::last_os_error());
            return None;
        }

        if SetSecurityDescriptorDacl(p_security_descriptor, 1, p_acl, 0) == 0{
            eprintln!("SetSecurityDescriptorDacl failed: {}", std::io::Error::last_os_error());
            return None;
        }

        sa.lpSecurityDescriptor = p_security_descriptor;

        Some(sa)
    }
}




pub fn duplicate_handle(handle: BorrowedHandle<'_>) -> io::Result<OwnedHandle> {
    let raw = duplicate_handle_inner(handle, None)?;
    unsafe { Ok(OwnedHandle::from_raw_handle(raw)) }
}
pub fn duplicate_handle_to_foreign(
    handle: BorrowedHandle<'_>,
    other_process: BorrowedHandle<'_>,
) -> io::Result<RawHandle> {
    duplicate_handle_inner(handle, Some(other_process))
}

fn duplicate_handle_inner(
    handle: BorrowedHandle<'_>,
    other_process: Option<BorrowedHandle<'_>>,
) -> io::Result<RawHandle> {
    let mut new_handle = INVALID_HANDLE_VALUE;
    let success = unsafe {
        let proc = GetCurrentProcess();
        DuplicateHandle(
            proc,
            handle.as_raw_handle(),
            other_process.map(|h| h.as_raw_handle()).unwrap_or(proc),
            &mut new_handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ) != 0
    };
    ok_or_ret_errno!(success => new_handle)
}

pub fn init_security_attributes() -> SECURITY_ATTRIBUTES {
    let mut a: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    a.nLength = size_of::<SECURITY_ATTRIBUTES>() as _;
    a
}
