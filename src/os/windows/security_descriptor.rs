use std::{alloc, borrow::Borrow, ffi::c_void, fmt::Debug, io};
use std::mem::size_of;
use windows_sys::Win32::Security::{InitializeSecurityDescriptor, IsValidSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR};
#[cfg(target_pointer_width = "64")]
pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 40;
#[cfg(target_pointer_width = "32")]
pub const SECURITY_DESCRIPTOR_MIN_LENGTH: usize = 20;
/// A borrowed [security descriptor][sd] which is known to be safe to use.
///
/// [sd]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct SecurityDescriptor(SECURITY_DESCRIPTOR);
impl Default for SecurityDescriptor {
    fn default() -> Self {
        let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let result = unsafe {
            InitializeSecurityDescriptor(
                &mut sd as *mut _ as *mut c_void,//
                windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION
            )
        };

        if result == 0 {
            unsafe { alloc::dealloc(&mut sd as *mut _ as *mut u8, std::alloc::Layout::new::<SECURITY_DESCRIPTOR>()) };
            panic!("Failed to initialize SECURITY_DESCRIPTOR: {}", io::Error::last_os_error());
        }

        SecurityDescriptor(sd)
    }
}
impl SecurityDescriptor {
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
    pub fn write_to_security_attributes(&self, attributes: &mut SECURITY_ATTRIBUTES) {
        attributes.lpSecurityDescriptor = self.as_ptr();
    }

    pub(super) fn create_security_attributes(
        slf: Option<&Self>,
        inheritable: bool,
    ) -> SECURITY_ATTRIBUTES {
        let mut attrs = unsafe { std::mem::zeroed::<SECURITY_ATTRIBUTES>() };
        if let Some(slf) = slf {
            slf.write_to_security_attributes(&mut attrs);
        }
        attrs.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        attrs.bInheritHandle = inheritable as i32;
        attrs
    }


    pub fn init_security_description() -> io::Result<PSECURITY_DESCRIPTOR> {
        let layout = std::alloc::Layout::from_size_align(size_of::<[u8; SECURITY_DESCRIPTOR_MIN_LENGTH]>() as _, 8).unwrap();
        let p_sd: PSECURITY_DESCRIPTOR = unsafe { alloc::alloc(layout) as PSECURITY_DESCRIPTOR };
        println!("need to free p_sd: {:?}", p_sd);

        // Inicializar el descriptor de seguridad
        let result = unsafe {
            InitializeSecurityDescriptor(p_sd, windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION)
        };
        if result == 0 {
            unsafe { alloc::dealloc(p_sd as *mut u8, layout) };
            return Err(io::Error::last_os_error());
        }
        Ok(p_sd)
    }
}

unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl Borrow<SECURITY_DESCRIPTOR> for SecurityDescriptor {
    #[inline]
    fn borrow(&self) -> &SECURITY_DESCRIPTOR {
        &self.0
    }
}
impl AsRef<SECURITY_DESCRIPTOR> for SecurityDescriptor {
    #[inline]
    fn as_ref(&self) -> &SECURITY_DESCRIPTOR {
        &self.0
    }
}

impl Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecurityDescriptor")
            .field(&self.0.Revision)
            .field(&self.0.Sbz1)
            .field(&self.0.Control)
            .field(&self.0.Owner)
            .field(&self.0.Group)
            .field(&self.0.Sacl)
            .field(&self.0.Dacl)
            .finish()
    }
}
