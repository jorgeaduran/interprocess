use super::LocalSocketStream;
use crate::{
    local_socket::ToLocalSocketName,
    os::windows::named_pipe::{
        pipe_mode::Bytes, PipeListener as GenericPipeListener, PipeListenerOptions,
    },
};
use std::{
    io,
    path::{Path, PathBuf},
};
use windows_sys::Win32::Security::{SE_DACL_PRESENT, SECURITY_DESCRIPTOR};
use crate::os::windows::SecurityDescriptor;

type PipeListener = GenericPipeListener<Bytes, Bytes>;

#[derive(Debug)]
pub struct LocalSocketListener(PipeListener);
impl LocalSocketListener {
    pub fn bind<'a>(name: impl ToLocalSocketName<'a>, bind_unsafe: bool) -> io::Result<Self> {
        let name = name.to_local_socket_name()?;
        let path = Path::new(name.inner());
        let mut options = PipeListenerOptions::new();
        options.path = if name.is_namespaced() {
            // PERF this allocates twice
            [Path::new(r"\\.\pipe\"), path]
                .iter()
                .collect::<PathBuf>()
                .into()
        } else {
            path.into()
        };
        if !bind_unsafe{
            let mut sd = SecurityDescriptor::default();
            unsafe{
                (*(sd.as_ptr() as *mut SECURITY_DESCRIPTOR)).Control = SE_DACL_PRESENT;
            }
            options.security_descriptor = Some(std::borrow::Cow::Owned(sd));

        }
        options.create().map(Self)
    }
    pub fn accept(&self) -> io::Result<LocalSocketStream> {
        let inner = self.0.accept()?;
        Ok(LocalSocketStream(inner))
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
    pub fn do_not_reclaim_name_on_drop(&mut self) {}
}
forward_into_handle!(LocalSocketListener);
