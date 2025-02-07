use super::winprelude::*;
use std::io;
use windows_sys::Win32::{
	Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS},
	System::Threading::GetCurrentProcess,
};

pub fn duplicate_handle(handle: BorrowedHandle<'_>) -> io::Result<OwnedHandle> {
	let raw = duplicate_handle_inner(handle, None)?;
	unsafe { Ok(OwnedHandle::from_raw_handle(raw as RawHandle)) }
}
pub fn duplicate_handle_to_foreign(
	handle: BorrowedHandle<'_>,
	other_process: BorrowedHandle<'_>,
) -> io::Result<RawHandle> {
	duplicate_handle_inner(handle, Some(other_process))
}

fn duplicate_handle_inner(
	handle: BorrowedHandle<'_>,
	other_process: Option<BorrowedHandle<'_>>,
) -> io::Result<RawHandle> {
	let mut new_handle = INVALID_HANDLE_VALUE;
	let success = unsafe {
		let proc = GetCurrentProcess();
		DuplicateHandle(
			proc,
			handle.as_int_handle(),
			other_process.map(|h| h.as_int_handle()).unwrap_or(proc),
			&mut new_handle,
			0,
			0,
			DUPLICATE_SAME_ACCESS,
		) != 0
	};
	ok_or_errno!(success => new_handle as _)
}
