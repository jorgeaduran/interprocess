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

type PipeListener = GenericPipeListener<Bytes, Bytes>;

#[derive(Debug)]
pub struct LocalSocketListener(PipeListener);
impl LocalSocketListener {
    pub fn bind<'a>(name: impl ToLocalSocketName<'a>, sec_d: Option<crate::os::windows::security_descriptor::SecurityDescriptor>) -> io::Result<Self> {
        let name = name.to_local_socket_name()?;
        let path = Path::new(name.inner());
        let mut options = PipeListenerOptions::new();


        options.path = if name.is_namespaced() {
            // PERF this allocates twice
            [Path::new(r"\\.\pipe\"), path].iter().collect::<PathBuf>().into()
        } else {
            path.into()
        };
        println!("options.path: {:?}", options.path);

        // Asignar el security descriptor con COW
        if let Some(sec_d) = sec_d {
            options.security_descriptor = Some(std::borrow::Cow::Owned(sec_d));
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
}
forward_into_handle!(LocalSocketListener);
