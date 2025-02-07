use super::{name_to_addr, ReclaimGuard, Stream};
use crate::local_socket::{traits, Name};
use std::{
	fmt::{self, Debug, Formatter},
	io,
	os::{
		fd::{AsFd, BorrowedFd, OwnedFd},
		unix::{io::AsRawFd, net::UnixListener},
	},
};

/// Wrapper around [`UnixListener`] that implements
/// [`Listener`](crate::local_socket::traits::Listener).
pub struct Listener {
	pub(super) listener: UnixListener,
	pub(super) reclaim: ReclaimGuard,
}
impl Listener {
	fn decode_listen_error(error: io::Error) -> io::Error {
		io::Error::from(match error.kind() {
			io::ErrorKind::AlreadyExists => io::ErrorKind::AddrInUse,
			_ => return error,
		})
	}

	pub(super) fn _bind(name: Name<'_>, keep_name: bool) -> io::Result<Self> {
		Ok(Self {
			listener: UnixListener::bind_addr(&name_to_addr(name.borrow())?)
				.map_err(Self::decode_listen_error)?,
			reclaim: keep_name
				.then_some(name.into_owned())
				.map(ReclaimGuard::new)
				.unwrap_or_default(),
		})
	}
}
impl crate::Sealed for Listener {}
impl traits::Listener for Listener {
	type Stream = Stream;

	#[inline]
	fn bind(name: Name<'_>) -> io::Result<Self> {
		Self::_bind(name, true)
	}
	#[inline]
	fn bind_without_name_reclamation(name: Name<'_>) -> io::Result<Self> {
		Self::_bind(name, false)
	}
	#[inline]
	fn accept(&self) -> io::Result<Stream> {
		// TODO make use of the second return value in some shape or form
		self.listener.accept().map(|(s, _)| Stream::from(s))
	}
	#[inline]
	fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
		self.listener.set_nonblocking(nonblocking)
	}
	fn do_not_reclaim_name_on_drop(&mut self) {
		self.reclaim.forget();
	}
}

impl Debug for Listener {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Listener")
			.field("fd", &self.listener.as_raw_fd())
			.field("reclaim", &self.reclaim)
			.finish()
	}
}

impl From<Listener> for UnixListener {
	fn from(mut l: Listener) -> Self {
		l.reclaim.forget();
		l.listener
	}
}

impl AsFd for Listener {
	#[inline]
	fn as_fd(&self) -> BorrowedFd<'_> {
		self.listener.as_fd()
	}
}
impl From<Listener> for OwnedFd {
	fn from(l: Listener) -> Self {
		UnixListener::from(l).into()
	}
}
impl From<OwnedFd> for Listener {
	fn from(fd: OwnedFd) -> Self {
		Listener {
			listener: fd.into(),
			reclaim: ReclaimGuard::default(),
		}
	}
}
