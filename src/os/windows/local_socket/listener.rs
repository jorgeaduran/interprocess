use super::LocalSocketStream;
use crate::{
    local_socket::ToLocalSocketName,
    os::windows::named_pipe::{pipe_mode, PipeListener as GenericPipeListener, PipeListenerOptions, PipeMode},
};
use std::io;
use crate::os::windows::security_descriptor::SecurityAttributes;

type PipeListener = GenericPipeListener<pipe_mode::Bytes, pipe_mode::Bytes>;

#[derive(Debug)]
pub struct LocalSocketListener(PipeListener);
impl LocalSocketListener {
    pub fn bind<'a>(name: impl ToLocalSocketName<'a>, security_attributes: Option<SecurityAttributes>) -> io::Result<Self> {
        let name = name.to_local_socket_name()?;
        let inner = PipeListenerOptions::new()
            .name(name.into_inner())
            .mode(PipeMode::Bytes)
            .security_attributes(security_attributes)
            .create()?;
        Ok(Self(inner))
    }
    pub fn accept(&self) -> io::Result<LocalSocketStream> {
        let inner = self.0.accept()?;
        Ok(LocalSocketStream(inner))
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }
}
