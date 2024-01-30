use std::{alloc, borrow::Borrow, ffi::c_void, fmt::Debug, io};
use std::mem::{size_of, zeroed};
use windows_sys::Win32::Security::{InitializeSecurityDescriptor, IsValidSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
/// Size in bytes of a minimal security descriptor on a 64-bit system.
#[cfg(target_pointer_width = "64")]
pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 40;
/// Size in bytes of a minimal security descriptor on a 32-bit system.
#[cfg(target_pointer_width = "32")]
pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 20;
/// A borrowed [security descriptor][sd] which is known to be safe to use.
///
/// [sd]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct SecurityAttributes(SECURITY_ATTRIBUTES);
impl Default for SecurityAttributes {
    // Default implementation for creating a new `SecurityDescriptor`.
    fn default() -> Self {
        let mut sd = SecurityAttributes::new();
        sd.set_inheritable(false);
        sd
    }
}
impl SecurityAttributes {
    /// Creates a new `SecurityAttributes` structure.
    /// The `SECURITY_DESCRIPTOR` structure is initialized to a default empty state.
    pub fn new() -> Self {
        let mut sa: SECURITY_ATTRIBUTES = unsafe { zeroed() };
        sa.nLength = size_of::<SECURITY_ATTRIBUTES>() as _;
        SecurityAttributes(sa)
    }
    /// Borrows the given security descriptor.
    ///
    /// # Safety
    /// - The `SECURITY_DESCRIPTOR` structure includes pointer fields which Windows later
    ///   dereferences. Having those pointers point to garbage, uninitialized memory or
    ///   non-dereferencable regions constitutes undefined behavior.
    /// - The pointers contained inside must not be aliased by mutable references.
    /// - `IsValidSecurityDescriptor()` must return `true` for the given value.
    #[inline]
    pub unsafe fn from_ref(r: &SECURITY_DESCRIPTOR) -> &Self {
        unsafe {
            let ret = std::mem::transmute::<_, &Self>(r);
            debug_assert!(IsValidSecurityDescriptor(ret.as_ptr()) == 1);
            ret
        }
    }
    /// Casts to the `void*` type seen in `SECURITY_ATTRIBUTES`.
    #[inline]
    pub fn as_ptr(&self) -> *mut c_void {
        (self as *const Self).cast_mut().cast()
    }
    /// Sets the security descriptor pointer of the given `SECURITY_ATTRIBUTES` structure to the
    /// security descriptor borrow of `self`.
    pub fn set_security_descriptor(&mut self, sd: *mut c_void) {
        self.0.lpSecurityDescriptor = sd;
    }

    /// Sets whether the handle created from this `SECURITY_ATTRIBUTES` structure is inheritable.
    pub fn set_inheritable(&mut self, inheritable: bool) {
        self.0.bInheritHandle = inheritable as i32;
    }

    /// deallocates the security descriptor
    pub fn free_security_descriptor(&mut self) {
        unsafe {
            alloc::dealloc(self.0.lpSecurityDescriptor as *mut u8, alloc::Layout::new::<SECURITY_DESCRIPTOR>());
        }
    }

    /// Initializes the security descriptor and returns a pointer to it.
    /// The caller is responsible for deallocating the memory.
    pub fn init_security_description(&self) -> io::Result<*mut c_void> {
        let layout = alloc::Layout::from_size_align(size_of::<[u8; SECURITY_DESCRIPTOR_MIN_LENGTH]>() as _, 8).unwrap();
        let p_sd: PSECURITY_DESCRIPTOR = unsafe { alloc::alloc(layout) as PSECURITY_DESCRIPTOR };

        let result = unsafe {
            InitializeSecurityDescriptor(
                p_sd,
                windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
            )
        };
        if result == 0 {
            unsafe { alloc::dealloc(p_sd as *mut u8, layout) };
            return Err(io::Error::last_os_error());
        }
        Ok(p_sd)
    }
}

unsafe impl Send for SecurityAttributes {}
unsafe impl Sync for SecurityAttributes {}

impl Borrow<SECURITY_ATTRIBUTES> for SecurityAttributes {
    #[inline]
    fn borrow(&self) -> &SECURITY_ATTRIBUTES {
        &self.0
    }
}
impl AsRef<SECURITY_ATTRIBUTES> for SecurityAttributes {
    #[inline]
    fn as_ref(&self) -> &SECURITY_ATTRIBUTES {
        &self.0
    }
}

impl Debug for SecurityAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityAttributes")
            .field("nLength", &self.0.nLength)
            .field("lpSecurityDescriptor", &self.0.lpSecurityDescriptor)
            .field("bInheritHandle", &self.0.bInheritHandle)
            .finish()
    }
}
