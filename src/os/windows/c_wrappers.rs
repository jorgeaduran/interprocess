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
