mod create_instance;
mod incoming;
mod options;

pub use {incoming::*, options::*};

use super::{PipeModeTag, PipeStream, PipeStreamRole, RawPipeStream};
use crate::{
	os::windows::{winprelude::*, FileHandle},
	poison_error, LOCK_POISON,
};
use std::{
	fmt::{self, Debug, Formatter},
	io,
	marker::PhantomData,
	mem::replace,
	ptr,
	sync::{
		atomic::{AtomicBool, Ordering::Relaxed},
		Mutex,
	},
};
use windows_sys::Win32::{Foundation::ERROR_PIPE_CONNECTED, System::Pipes::ConnectNamedPipe};

/// The server for a named pipe, listening for connections to clients and producing pipe streams.
///
/// Note that this type does not correspond to any Win32 object, and is an invention of Interprocess
/// in its entirety.
///
/// The only way to create a `PipeListener` is to use [`PipeListenerOptions`]. See its documentation
/// for more.
// TODO examples
pub struct PipeListener<Rm: PipeModeTag, Sm: PipeModeTag> {
	config: PipeListenerOptions<'static>, // We need the options to create new instances
	nonblocking: AtomicBool,
	stored_instance: Mutex<FileHandle>,
	_phantom: PhantomData<(Rm, Sm)>,
}
impl<Rm: PipeModeTag, Sm: PipeModeTag> PipeListener<Rm, Sm> {
	const STREAM_ROLE: PipeStreamRole = PipeStreamRole::get_for_rm_sm::<Rm, Sm>();

	/// Blocks until a client connects to the named pipe, creating a `Stream` to communicate with
	/// the pipe.
	///
	/// See `incoming` for an iterator version of this.
	pub fn accept(&self) -> io::Result<PipeStream<Rm, Sm>> {
		let instance_to_hand_out = {
			let mut stored_instance = self.stored_instance.lock().map_err(poison_error)?;
			// Doesn't actually even need to be atomic to begin with, but it's simpler and more
			// convenient to do this instead. The mutex takes care of ordering.
			let nonblocking = self.nonblocking.load(Relaxed);
			block_on_connect(stored_instance.as_handle())?;
			let new_instance = self.create_instance(nonblocking)?;
			replace(&mut *stored_instance, new_instance)
		};

		let raw = RawPipeStream::new_server(instance_to_hand_out);

		Ok(PipeStream::new(raw))
	}
	/// Creates an iterator which accepts connections from clients, blocking each time `next()` is
	/// called until one connects.
	#[inline(always)]
	pub fn incoming(&self) -> Incoming<'_, Rm, Sm> {
		Incoming(self)
	}
	/// Enables or disables the nonblocking mode for all existing instances of the listener and
	/// future ones. By default, it is disabled.
	///
	/// This should generally be done during creation, using the
	/// [`nonblocking` field](PipeListenerOptions::nonblocking) of the creation options (unless
	/// there's a good reason not to), which allows making one less system call during creation.
	///
	/// See the documentation of the aforementioned field for the exact effects of enabling this
	/// mode.
	pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
		let instance = self.stored_instance.lock().map_err(poison_error)?;
		// Doesn't actually even need to be atomic to begin with, but it's simpler and more
		// convenient to do this instead. The mutex takes care of ordering.
		self.nonblocking.store(nonblocking, Relaxed);
		super::set_nonblocking_given_readmode(instance.as_handle(), nonblocking, Rm::MODE)?;
		// Make it clear that the lock survives until this moment.
		drop(instance);
		Ok(())
	}

	fn create_instance(&self, nonblocking: bool) -> io::Result<FileHandle> {
		self.config
			.create_instance(false, nonblocking, false, Self::STREAM_ROLE, Rm::MODE)
			.map(FileHandle::from)
	}
}
impl<Rm: PipeModeTag, Sm: PipeModeTag> Debug for PipeListener<Rm, Sm> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("PipeListener")
			.field("config", &self.config)
			.field("instance", &self.stored_instance)
			.field("nonblocking", &self.nonblocking.load(Relaxed))
			.finish()
	}
}
impl<Rm: PipeModeTag, Sm: PipeModeTag> From<PipeListener<Rm, Sm>> for OwnedHandle {
	fn from(p: PipeListener<Rm, Sm>) -> Self {
		p.stored_instance.into_inner().expect(LOCK_POISON).into()
	}
}

fn block_on_connect(handle: BorrowedHandle<'_>) -> io::Result<()> {
	let success = unsafe { ConnectNamedPipe(handle.as_int_handle(), ptr::null_mut()) != 0 };
	if success {
		Ok(())
	} else {
		let last_error = io::Error::last_os_error();
		if last_error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) {
			Ok(())
		} else {
			Err(last_error)
		}
	}
}
