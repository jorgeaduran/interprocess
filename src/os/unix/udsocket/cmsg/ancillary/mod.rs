//! Zero-copy serialization and deserialization of Unix domain socket ancillary data.
//!
//! This module features safe wrappers for well-defined types of Unix domain socket control messages, allowing for their
//! serialization without the use of unsafe code. It also includes parsers for those types of control messages and a
//! catch-all parser that can parse all control message types that are known to this module.

// TODO SCM_CREDS2 from FreeBSD
// TODO SCM_TIMESTAMP, also the one with nanosecond precision

#[cfg_attr(
    feature = "doc_cfg",
    doc(cfg(any(
        target_os = "linux",
        target_os = "emscripten",
        target_os = "redox",
        target_os = "freebsd",
        target_os = "dragonfly",
    )))
)]
#[cfg(any(uds_ucred, uds_cmsgcred))]
pub mod credentials;
pub mod file_descriptors;

mod dispatcher;
pub use dispatcher::*;

use super::*;
use std::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};

const LEVEL: c_int = libc::SOL_SOCKET;

/// An ancillary data wrapper that can be converted to a control message.
pub trait ToCmsg {
    /// Invokes the conversion to an ancillary message. The provided closure will receive the conversion result ephemerally.
    ///
    /// It's a logic error for this function to not call `add_fn`, and an unconditional assertion will panic in the circumstance when it doesn't.
    fn add_to_buffer(&self, add_fn: impl FnOnce(Cmsg<'_>));
    // FIXME is the closure necessary?
}

/// An ancillary data wrapper than can be parsed from a control message.
///
/// As a trait bound, this will typically require the use of an HRTB: `T: for<'a> FromCmsg<'a>`.
///
/// Implementations of this trait are expected to return correct error information in good faith. Returning the wrong expected ancillary message type/level in [`WrongType`](ParseErrorKind::WrongType)/[`WrongLevel`](ParseErrorKind::WrongLevel) can lead to an infinite loop.
pub trait FromCmsg<'a>: Sized {
    /// The error type produced for malformed payloads, typically [`Infallible`].
    type MalformedPayloadError;

    /// Attempts to extract data from `cmsg` into a new instance of `Self`, returning `None` if the control message is of the wrong level, type or has malformed content.
    fn try_parse(cmsg: Cmsg<'a>) -> ParseResult<'a, Self, Self::MalformedPayloadError>;
}

/// The result type for [`FromCmsg`].
pub type ParseResult<'a, T, E = Infallible> = Result<T, ParseError<'a, E>>;

/// The error type for [`FromCmsg`].
#[derive(Debug)]
pub struct ParseError<'a, E = Infallible> {
    /// The control message passed to `try_parse()`, so that parsing could be retried with another type.
    pub cmsg: Cmsg<'a>,
    /// The actual error information.
    pub kind: ParseErrorKind<E>,
}
impl<'a, E> ParseError<'a, E> {
    /// Maps the malformed payload error type using the given transformation function.
    #[inline]
    pub fn map_payload_err<F>(self, f: impl FnOnce(E) -> F) -> ParseError<'a, F> {
        let Self { cmsg, kind } = self;
        ParseError {
            cmsg,
            kind: kind.map_payload_err(f),
        }
    }
}
impl<'a, E: Display> Display for ParseError<'a, E> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.kind, f)
    }
}
impl<E: Debug + Display> Error for ParseError<'_, E> {}

/// The specific error kind contained in [`ParseError`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParseErrorKind<E = Infallible> {
    /// The value of `cmsg_level` doesn't match.
    WrongLevel {
        /// The `cmsg_level` that was expected, or `None` if multiple are allowed or no particular one was expected.
        expected: Option<c_int>,
        /// The `cmsg_level` that was received.
        got: c_int,
    },
    /// The value of `cmsg_type` doesn't match.
    WrongType {
        /// The `cmsg_type` that was expected, or `None` if multiple are allowed or no particular one was expected.
        expected: Option<c_int>,
        /// The `cmsg_type` that was received.
        got: c_int,
    },
    /// The control message data does not conform to the format of the ancillary data message type, with an explanatory error value.
    MalformedPayload(E),
}
impl<E> ParseErrorKind<E> {
    /// Wraps up the error into a [`ParseError`], with the given `cmsg` as the return-to-caller control message ownership item.
    #[inline]
    pub fn wrap(self, cmsg: Cmsg<'_>) -> ParseError<'_, E> {
        ParseError { cmsg, kind: self }
    }
    /// Maps the malformed payload error type using the given transformation function.
    #[inline]
    pub fn map_payload_err<F>(self, f: impl FnOnce(E) -> F) -> ParseErrorKind<F> {
        match self {
            Self::MalformedPayload(e) => ParseErrorKind::MalformedPayload(f(e)),
            Self::WrongLevel { expected, got } => ParseErrorKind::WrongLevel { expected, got },
            Self::WrongType { expected, got } => ParseErrorKind::WrongType { expected, got },
        }
    }
}
impl<E: Display> Display for ParseErrorKind<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use ParseErrorKind::*;
        let msg_base = match self {
            WrongLevel { .. } => "wrong cmsg_level",
            WrongType { .. } => "wrong cmsg_type",
            MalformedPayload(..) => "malformed control message",
        };

        match self {
            WrongLevel { expected, got } | WrongType { expected, got } => {
                write!(f, "{msg_base} (")?;
                if let Some(expected) = expected {
                    write!(f, "expected {expected}, ")?;
                }
                write!(f, "got {got}")
            }
            MalformedPayload(e) => write!(f, "{msg_base}: {e}"),
        }
    }
}
impl<E: Debug + Display> Error for ParseErrorKind<E> {}

/// A [`MalformedPayload`](ParseErrorKind::MalformedPayload) error indicating that the ancillary message size dosen't
/// match that of the platform-specific credentials structure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SizeMismatch {
    /// Expected size of the ancillary message. This value may or may not be derived from some of the message's
    /// contents.
    pub expected: usize,
    /// Actual size of the ancillary message.
    pub got: usize,
}
impl Display for SizeMismatch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { expected, got } = self;
        write!(f, "ancillary payload size mismatch (expected {expected}, got {got})")
    }
}
impl Error for SizeMismatch {}

fn check_level<E>(cmsg: Cmsg<'_>) -> ParseResult<'_, Cmsg<'_>, E> {
    let got = cmsg.cmsg_level();
    if got != LEVEL {
        return Err(ParseErrorKind::WrongLevel {
            expected: Some(LEVEL),
            got,
        }
        .wrap(cmsg));
    }
    Ok(cmsg)
}
fn check_type<E>(cmsg: Cmsg<'_>, expected: c_int) -> ParseResult<'_, Cmsg<'_>, E> {
    let got = cmsg.cmsg_type();
    if got != expected {
        return Err(ParseErrorKind::WrongType {
            expected: Some(expected),
            got,
        }
        .wrap(cmsg));
    }
    Ok(cmsg)
}
fn check_level_and_type<E>(mut cmsg: Cmsg<'_>, expected: c_int) -> ParseResult<'_, Cmsg<'_>, E> {
    cmsg = check_level(cmsg)?;
    check_type(cmsg, expected)
}

fn check_size<E: From<SizeMismatch>>(cmsg: Cmsg<'_>, expected: usize) -> ParseResult<'_, Cmsg<'_>, E> {
    let got = cmsg.data().len();
    if got != expected {
        return Err(ParseErrorKind::MalformedPayload(E::from(SizeMismatch { expected, got })).wrap(cmsg));
    }
    Ok(cmsg)
}
