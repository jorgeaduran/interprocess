use super::*;
use crate::os::windows::{
	named_pipe::{pipe_mode, PipeMode, PipeModeTag, WaitTimeout},
	path_conversion::*,
	SecurityDescriptor,
};
use std::{borrow::Cow, io, marker::PhantomData, num::NonZeroU8, sync::Mutex};
use widestring::{u16cstr, U16CStr};

/// Allows for thorough customization of [`PipeListener`]s during creation.
// TODO allow partial modification for later instances
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PipeListenerOptions<'a> {
	/// Specifies the name for the named pipe. The necessary `\\.\pipe\` prefix is *not*
	/// automatically prepended!
	pub path: Cow<'a, U16CStr>,
	/// Specifies how data is written into the data stream. This is required in all cases,
	/// regardless of whether the pipe is inbound, outbound or duplex, since this affects all data
	/// being written into the pipe, not just the data written by the server.
	pub mode: PipeMode,
	/// Specifies whether nonblocking mode will be enabled for all stream instances upon creation.
	/// By default, it is disabled.
	///
	/// There are two ways in which the listener is affected by nonblocking mode:
	/// -	Whenever [`accept()`] is called or [`incoming()`] is being iterated through, if there is
	/// 	no client currently attempting to connect to the named pipe server, the method will return
	/// 	immediately with the [`WouldBlock`](io::ErrorKind::WouldBlock) error instead of blocking
	/// 	until one arrives.
	/// -	The streams created by [`accept()`] and [`incoming()`] behave similarly to how client-side
	/// 	streams behave in nonblocking mode. See the documentation for `set_nonblocking` for an
	/// 	explanation of the exact effects.
	///
	/// [`accept()`]: PipeListener::accept
	/// [`incoming()`]: PipeListener::incoming
	pub nonblocking: bool,
	/// Specifies the maximum amount of instances of the pipe which can be created, i.e. how many
	/// clients can be communicated with at once. If set to 1, trying to create multiple instances
	/// at the same time will return an error. If set to `None`, no limit is applied. The value 255
	/// is not allowed because of Windows limitations.
	pub instance_limit: Option<NonZeroU8>,
	/// Enables write-through mode, which applies only to network connections to the pipe. If
	/// enabled, sending to the pipe will always block until all data is delivered to the other end
	/// instead of piling up in the kernel's network buffer until a certain amount of data
	/// accamulates or a certain period of time passes, which is when the system actually sends the
	/// contents of the buffer over the network.
	///
	/// Not required for pipes which are restricted to local connections only. If debug assertions
	/// are enabled, setting this parameter on a local-only pipe will cause a panic when the pipe is
	/// created; in release builds, creation will successfully complete without any errors and the
	/// flag will be completely ignored.
	pub write_through: bool,
	/// Enables remote machines to connect to the named pipe over the network.
	pub accept_remote: bool,
	/// Specifies how big the input buffer should be. The system will automatically adjust this size
	/// to align it as required or clip it by the minimum or maximum buffer size.
	pub input_buffer_size_hint: u32,
	/// Specifies how big the output buffer should be. The system will automatically adjust this
	/// size to align it as required or clip it by the minimum or maximum buffer size.
	pub output_buffer_size_hint: u32,
	/// The default timeout clients use when connecting. Used unless another timeout is specified
	/// when waiting by a client.
	pub wait_timeout: WaitTimeout,
	/// The security descriptor to create the named pipe server with.
	pub security_descriptor: Option<Cow<'a, SecurityDescriptor>>,
	/// Whether the resulting handle is to be inheritable by child processes or not.
	///
	/// There is little to no reason for this to ever be `true`.
	pub inheritable: bool,
}
macro_rules! genset {
	($name:ident : $ty:ty) => {
		#[doc = concat!(
			"Sets the [`",
			stringify!($name),
			"`](#structfield.", stringify!($name),
			") parameter to the specified value."
		)]
		#[must_use = "builder setters take the entire structure and return the result"]
		// FIXME this Into bound probably doesn't work all too well for `path`
		pub fn $name(mut self, $name: impl Into<$ty>) -> Self {
			self.$name = $name.into();
			self
		}
	};
	($($name:ident : $ty:ty),+ $(,)?) => {
		$(genset!($name: $ty);)+
	};
}
impl<'a> PipeListenerOptions<'a> {
	/// Creates a new builder with default options.
	#[allow(clippy::indexing_slicing)] // are you fucking with me
	pub fn new() -> Self {
		Self {
			path: Cow::Borrowed(u16cstr!("")),
			mode: PipeMode::Bytes,
			nonblocking: false,
			instance_limit: None,
			write_through: false,
			accept_remote: false,
			input_buffer_size_hint: 512,
			output_buffer_size_hint: 512,
			wait_timeout: WaitTimeout::DEFAULT,
			security_descriptor: None,
			inheritable: false,
		}
	}
	/// Clones configuration options which are not owned by value and returns a copy of the original
	/// option table which is guaranteed not to borrow anything and thus ascribes to the `'static`
	/// lifetime.
	pub fn to_owned(&self) -> PipeListenerOptions<'static> {
		// We need this ugliness because the compiler does not understand that
		// PipeListenerOptions<'a> can coerce into PipeListenerOptions<'static> if we manually
		// replace the name field with Cow::Owned and just copy all other elements over thanks
		// to the fact that they don't contain a mention of the lifetime 'a. Tbh we need an
		// RFC for this, would be nice.
		PipeListenerOptions {
			path: Cow::Owned(self.path.clone().into_owned()),
			mode: self.mode,
			nonblocking: self.nonblocking,
			instance_limit: self.instance_limit,
			write_through: self.write_through,
			accept_remote: self.accept_remote,
			input_buffer_size_hint: self.input_buffer_size_hint,
			output_buffer_size_hint: self.output_buffer_size_hint,
			wait_timeout: self.wait_timeout,
			security_descriptor: match self.security_descriptor {
				Some(Cow::Owned(o)) => Some(Cow::Owned(o)),
				Some(Cow::Borrowed(b)) => Some(Cow::Owned(*b)),
				None => None,
			},
			inheritable: self.inheritable,
		}
	}

	/// Sets the [`path`](#structfield.path) parameter to the specified value.
	#[inline]
	pub fn path(mut self, path: impl ToWtf16<'a>) -> Self {
		self.path = path.to_wtf_16().expect(EXPECT_WTF16);
		self
	}
	genset! {
		mode: PipeMode,
		nonblocking: bool,
		instance_limit: Option<NonZeroU8>,
		write_through: bool,
		accept_remote: bool,
		input_buffer_size_hint: u32,
		output_buffer_size_hint: u32,
		wait_timeout: WaitTimeout,
		security_descriptor: Option<Cow<'a, SecurityDescriptor>>,
		inheritable: bool,
	}

	/// Creates the pipe listener from the builder. The `Rm` and `Sm` generic arguments specify the
	/// type of pipe stream that the listener will create, thus determining the direction of the
	/// pipe and its mode.
	///
	/// # Errors
	/// In addition to regular OS errors, an error will be returned if the given `Rm` is
	/// [`pipe_mode::Messages`], but the `mode` field isn't also [`pipe_mode::Messages`].
	pub fn create<Rm: PipeModeTag, Sm: PipeModeTag>(&self) -> io::Result<PipeListener<Rm, Sm>> {
		let (owned_config, instance) =
			self._create(PipeListener::<Rm, Sm>::STREAM_ROLE, Rm::MODE)?;
		let nonblocking = owned_config.nonblocking.into();
		Ok(PipeListener {
			config: owned_config,
			nonblocking,
			stored_instance: Mutex::new(instance),
			_phantom: PhantomData,
		})
	}
	/// Alias for [`.create()`](Self::create) with the same `Rm` and `Sm`.
	#[inline]
	pub fn create_duplex<M: PipeModeTag>(&self) -> io::Result<PipeListener<M, M>> {
		self.create::<M, M>()
	}
	/// Alias for [`.create()`](Self::create) with an `Sm` of [`pipe_mode::None`].
	#[inline]
	pub fn create_recv_only<Rm: PipeModeTag>(
		&self,
	) -> io::Result<PipeListener<Rm, pipe_mode::None>> {
		self.create::<Rm, pipe_mode::None>()
	}
	/// Alias for [`.create()`](Self::create) with an `Rm` of [`pipe_mode::None`].
	#[inline]
	pub fn create_send_only<Sm: PipeModeTag>(
		&self,
	) -> io::Result<PipeListener<pipe_mode::None, Sm>> {
		self.create::<pipe_mode::None, Sm>()
	}
}
impl Default for PipeListenerOptions<'_> {
	#[inline(always)]
	fn default() -> Self {
		Self::new()
	}
}
