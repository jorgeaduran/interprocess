//! Local sockets, an IPC primitive featuring a server and multiple clients connecting to that
//! server using a filesystem path inside a special namespace, each having a private connection to
//! that server.
//!
//! ## Implementation types
//! Local sockets are not a real IPC method implemented by the OS – they exist to smooth out the
//! difference between two types of underlying implementation: **Unix domain sockets** and
//! **Windows named pipes**. The [`ImplType`] enumeration documents them and provides methods to
//! query whether they are available and their implementation specifics.
//!
//! ### Implementation properties
//! Implementations of the exact same IPC primitive can have subtly different feature sets on
//! different platforms and even on different versions of the same OS. For example, only on Linux
//! and Windows do Unix-domain sockets support the "anonymous namespace" (and thus feature
//! [`NameTypeSupport::Both`]); on FreeBSD, macOS and the likes, only file paths are available.
//!
//! The [`ImplProperties`] struct, as obtained through [`ImplType`]'s methods, is a source of
//! information on all possible differences between different implementations of local sockets. This
//! is to say that equal [`ImplProperties`] correspond to the same observable behavior of the IPC
//! primitive – if there are any other differences that affect the public API but are not documented
//! by [`ImplProperties`] (besides the mere fact that different IPC primitives use different system
//! APIs), that's a bug in Interprocess!
//!
//! ### Platform-specific namespaces
//! Since only Linux supports putting Unix-domain sockets in a separate namespace which is isolated
//! from the filesystem, the [`Name`] type is used to identify local sockets rather than `OsStr` or
//! `OsString`: on Unix platforms other than Linux, which includes macOS, all flavors of BSD and
//! possibly other Unix-like systems, the only way to name a Unix-domain socket is to use a
//! filesystem path. As such, those platforms don't have the namespaced socket creation method
//! available. Complicatng matters further, Windows does not support named pipes in the normal
//! filesystem, meaning that namespaced local sockets are the only available method on Windows.
//!
//! To solve this issue, [`Name`] has to be created with a specific name type in mind, with a
//! [`NameTypeSupport`] query being necessary to decide on an appropriate socket name.
//!
//! ## Differences from regular sockets
//! A few missing features, primarily on Windows, require local sockets to omit some important
//! functionality, because code relying on it wouldn't be portable. Some notable differences are:
//! -	No `.shutdown()` – your communication protocol must manually negotiate end of transmission.
//! 	Notably, `.read_to_string()` and `.read_all()` will always block indefinitely at some point.
//! -	No datagram sockets – the difference in semantics between connectionless datagram Unix-domain
//! 	sockets and connection-based named message pipes on Windows does not allow bridging those two
//! 	into a common API. You can emulate datagrams on top of streams anyway, so no big deal, right?

#[macro_use]
mod enumdef;

mod name;
mod name_type_support;
mod to_name;
mod stream {
	pub(super) mod r#enum;
	pub(super) mod r#trait;
}
mod listener {
	pub(super) mod r#enum;
	pub(super) mod r#trait;
}

pub use {listener::r#enum::*, name::*, name_type_support::*, stream::r#enum::*, to_name::*};

/// Traits representing the interface of local sockets.
pub mod traits {
	pub use super::{listener::r#trait::*, stream::r#trait::*};
}

/// Re-exports of [traits](traits) done in a way that doesn't pollute the scope, as well as
/// of the enum-dispatch types with their names prefixed with `LocalSocket`.
pub mod prelude {
	pub use super::{
		traits::{Listener as _, ListenerExt as _, Stream as _},
		Listener as LocalSocketListener, Stream as LocalSocketStream,
	};
}

/// Asynchronous local sockets which work with the Tokio runtime and event loop.
///
/// The Tokio integration allows the local socket streams and listeners to be notified by the OS
/// kernel whenever they're ready to be received from of sent to, instead of spawning threads just
/// to put them in a wait state of blocking on the I/O.
///
/// Types from this module will *not* work with other async runtimes, such as `async-std` or `smol`,
/// since the Tokio types' methods will panic whenever they're called outside of a Tokio runtime
/// context. Open an issue if you'd like to see other runtimes supported as well.
#[cfg(feature = "tokio")]
#[cfg_attr(feature = "doc_cfg", doc(cfg(feature = "tokio")))]
pub mod tokio {
	mod listener;
	mod stream;
	pub use {listener::*, stream::*};
}

mod concurrency_detector;

pub(crate) use concurrency_detector::*;

// TODO extension traits in crate::os for exposing some OS-specific functionality here
// TODO remove that whole ImplProperties thing in favor of a new trait-based system
