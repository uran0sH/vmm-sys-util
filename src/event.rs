// SPDX-License-Identifier: BSD-3-Clause
//! This is an abstraction for eventfd and pipefd

use libc::{c_void, dup, read, write};
use std::mem;
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
    result,
};

/// EventSender
#[derive(Debug)]
pub struct EventSender {
    fd: File,
}

impl EventSender {
    /// Write a value to the EventSender's fd
    pub fn write(&self) -> result::Result<(), io::Error> {
        let v = 1u64;
        // SAFETY: This is safe because we made this fd and the pointer we pass
        // can not overflow because we give the syscall's size parameter properly.
        let ret = unsafe {
            write(
                self.as_raw_fd(),
                &v as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret <= 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Clone this EventFd.
    ///
    /// This internally creates a new file descriptor and it will share the same
    /// underlying count within the kernel.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate vmm_sys_util;
    /// use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
    ///
    /// let evt = EventFd::new(EFD_NONBLOCK).unwrap();
    /// let evt_clone = evt.try_clone().unwrap();
    /// evt.write(923).unwrap();
    /// assert_eq!(evt_clone.read().unwrap(), 923);
    /// ```
    pub fn try_clone(&self) -> result::Result<EventSender, io::Error> {
        // SAFETY: This is safe because we made this fd and properly check that it returns
        // without error.
        let ret = unsafe { dup(self.as_raw_fd()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(EventSender {
                // SAFETY: This is safe because we checked ret for success and know the kernel
                // gave us an fd that we own.
                fd: unsafe { File::from_raw_fd(ret) },
            })
        }
    }
}

impl AsRawFd for EventSender {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for EventSender {
    unsafe fn from_raw_fd(fd: std::os::unix::prelude::RawFd) -> Self {
        EventSender {
            fd: File::from_raw_fd(fd),
        }
    }
}

/// EventReceiver
#[derive(Debug)]
pub struct EventReceiver {
    fd: File,
}

impl AsRawFd for EventReceiver {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for EventReceiver {
    unsafe fn from_raw_fd(fd: std::os::unix::prelude::RawFd) -> Self {
        EventReceiver {
            fd: File::from_raw_fd(fd),
        }
    }
}

impl EventReceiver {
    /// Read a value from the fd.
    pub fn read(&self) -> result::Result<u64, io::Error> {
        let mut buf: u64 = 0;
        // SAFETY: This is safe because we made this fd and the pointer we
        // pass can not overflow because we give the syscall's size parameter properly.
        let ret = unsafe {
            read(
                self.as_raw_fd(),
                &mut buf as *mut u64 as *mut c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(buf)
        }
    }

    /// Clone this EventFd.
    ///
    /// This internally creates a new file descriptor and it will share the same
    /// underlying count within the kernel.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate vmm_sys_util;
    /// use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
    ///
    /// let evt = EventFd::new(EFD_NONBLOCK).unwrap();
    /// let evt_clone = evt.try_clone().unwrap();
    /// evt.write(923).unwrap();
    /// assert_eq!(evt_clone.read().unwrap(), 923);
    /// ```
    pub fn try_clone(&self) -> result::Result<EventReceiver, io::Error> {
        // SAFETY: This is safe because we made this fd and properly check that it returns
        // without error.
        let ret = unsafe { dup(self.as_raw_fd()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(EventReceiver {
                // SAFETY: This is safe because we checked ret for success and know the kernel
                // gave us an fd that we own.
                fd: unsafe { File::from_raw_fd(ret) },
            })
        }
    }
}
