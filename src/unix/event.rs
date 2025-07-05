// SPDX-License-Identifier: BSD-3-Clause
//! This is an abstract EventNotifer and EventConsumer for eventfd and pipefd

use std::io::{Read, Write};
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    result,
};

bitflags::bitflags! {
    /// EventFlag
    /// This enum is used to define flags for the event notifier and consumer.
    pub struct EventFlag: u8 {
        /// Non-blocking flag
        const NONBLOCK = 1 << 0;
        /// Close-on-exec flag
        const CLOEXEC = 1 << 1;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl From<EventFlag> for i32 {
    fn from(flag: EventFlag) -> Self {
        let mut result = 0;
        if flag.contains(EventFlag::NONBLOCK) {
            result |= libc::EFD_NONBLOCK;
        }
        if flag.contains(EventFlag::CLOEXEC) {
            result |= libc::EFD_CLOEXEC;
        }
        result
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl From<EventFlag> for i32 {
    fn from(flag: EventFlag) -> Self {
        let mut result = 0;
        if flag.contains(EventFlag::NONBLOCK) {
            result |= libc::O_NONBLOCK;
        }
        if flag.contains(EventFlag::CLOEXEC) {
            result |= libc::FD_CLOEXEC;
        }
        result
    }
}

/// EventNotifier
/// This is a generic event notifier that can be used with eventfd or pipefd.
/// It allows writing a value to the file descriptor to notify an event.
///
/// # Examples
///
/// ```
/// use std::os::fd::FromRawFd;
/// use std::os::unix::io::IntoRawFd;
/// use vmm_sys_util::event::EventNotifier;
/// let (_, writer) = std::io::pipe().expect("Failed to create pipe");
/// let notifier = unsafe { EventNotifier::from_raw_fd(writer.into_raw_fd()) };
/// ```
#[derive(Debug)]
pub struct EventNotifier {
    fd: File,
}

impl EventNotifier {
    /// Write a value to the EventNotifier's fd
    /// Writing 1 to fd is for compatibility with Eventfd
    pub fn notify(&self) -> result::Result<(), io::Error> {
        let v = 1u64;
        (&self.fd).write_all(&v.to_ne_bytes())
    }

    /// Clone this EventNotifier.
    pub fn try_clone(&self) -> result::Result<EventNotifier, io::Error> {
        Ok(EventNotifier {
            fd: self.fd.try_clone()?,
        })
    }
}

impl AsRawFd for EventNotifier {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for EventNotifier {
    unsafe fn from_raw_fd(fd: std::os::unix::prelude::RawFd) -> Self {
        EventNotifier {
            fd: File::from_raw_fd(fd),
        }
    }
}

impl IntoRawFd for EventNotifier {
    fn into_raw_fd(self) -> std::os::unix::prelude::RawFd {
        self.fd.into_raw_fd()
    }
}

/// EventReceiver
/// This is a generic event consumer that can be used with eventfd or pipefd.
/// It allows reading a value from the file descriptor to consume an event.
///
/// # Examples
///
/// ```
/// use std::os::fd::FromRawFd;
/// use std::os::unix::io::IntoRawFd;
/// use vmm_sys_util::event::EventConsumer;
/// let (reader, _) = std::io::pipe().expect("Failed to create pipe");
/// let consumer = unsafe { EventConsumer::from_raw_fd(reader.into_raw_fd()) };
/// ```
#[derive(Debug)]
pub struct EventConsumer {
    fd: File,
}

impl EventConsumer {
    /// Read a value from the EventConsumer.
    pub fn consume(&self) -> result::Result<(), io::Error> {
        let mut buf = [0u8; size_of::<u64>()];
        (&self.fd).read_exact(buf.as_mut_slice()).map(|_| Ok(()))?
    }

    /// Clone this EventConsumer.
    pub fn try_clone(&self) -> result::Result<EventConsumer, io::Error> {
        Ok(EventConsumer {
            fd: self.fd.try_clone()?,
        })
    }
}

impl AsRawFd for EventConsumer {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for EventConsumer {
    unsafe fn from_raw_fd(fd: std::os::unix::prelude::RawFd) -> Self {
        EventConsumer {
            fd: File::from_raw_fd(fd),
        }
    }
}

impl IntoRawFd for EventConsumer {
    fn into_raw_fd(self) -> std::os::unix::prelude::RawFd {
        self.fd.into_raw_fd()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn fcntl_getfl_and_setfl(fd: i32, flag: i32) -> std::result::Result<(), io::Error> {
    // SAFETY: Safe because we check the fd is valid and check the return value.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Safe because we check the fd is valid and check the return value.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | flag) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fcntl_getfd_and_setfd(fd: i32, flag: i32) -> std::result::Result<(), io::Error> {
    // SAFETY: Safe because we check the fd is valid and check the return value.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Safe because we check the fd is valid and check the return value.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | flag) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Create a new EventNotifier and EventConsumer using a pipe.
///
/// # Arguments
///
/// * `flag` - Flags to set on the file descriptor, such as `EventFlag::NONBLOCK` or `EventFlag::CLOEXEC`.
///
/// # Examples
///
/// ```
/// use vmm_sys_util::event::{new_event_consumer_and_notifier, EventFlag};
/// let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK)
///     .expect("Failed to create notifier and consumer");
/// notifier.notify().unwrap();
/// assert!(consumer.consume().is_ok());
/// ```
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn new_event_consumer_and_notifier(
    flag: EventFlag,
) -> std::result::Result<(EventConsumer, EventNotifier), io::Error> {
    // Use a pipe for non-Linux platforms.
    use std::os::fd::RawFd;
    let mut fds: [RawFd; 2] = [-1, -1];
    // SAFETY: Safe because we check the fd is valid and check the return value.
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if flag.contains(EventFlag::NONBLOCK) {
        fcntl_getfl_and_setfl(fds[0], libc::O_NONBLOCK)?;
        fcntl_getfl_and_setfl(fds[1], libc::O_NONBLOCK)?;
    }
    if flag.contains(EventFlag::CLOEXEC) {
        use libc::FD_CLOEXEC;

        fcntl_getfd_and_setfd(fds[0], FD_CLOEXEC)?;
        fcntl_getfd_and_setfd(fds[1], FD_CLOEXEC)?;
    }
    // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
    let consumer = unsafe { EventConsumer::from_raw_fd(fds[0].into_raw_fd()) };
    // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
    let notifier = unsafe { EventNotifier::from_raw_fd(fds[1].into_raw_fd()) };
    Ok((consumer, notifier))
}

/// Create a new EventNotifier and EventConsumer using eventfd.
///
/// # Arguments
///
/// * `flag` - Flags to set on the file descriptor, such as `EventFlag::NONBLOCK` or `EventFlag::CLOEXEC`.
///
/// # Examples
///
/// ```
/// use vmm_sys_util::event::{new_event_consumer_and_notifier, EventFlag};
/// let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK)
///     .expect("Failed to create consumer and notifier");
/// notifier.notify().unwrap();
/// assert!(consumer.consume().is_ok());
/// ```
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn new_event_consumer_and_notifier(
    flag: EventFlag,
) -> std::result::Result<(EventConsumer, EventNotifier), io::Error> {
    let eventfd = crate::linux::eventfd::EventFd::new(flag.into())?;
    let eventfd_clone = eventfd.try_clone()?;
    if flag.contains(EventFlag::CLOEXEC) {
        fcntl_getfd_and_setfd(eventfd_clone.as_raw_fd(), libc::FD_CLOEXEC)?;
    }
    // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
    let consumer = unsafe { EventConsumer::from_raw_fd(eventfd_clone.into_raw_fd()) };
    // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
    let notifier = unsafe { EventNotifier::from_raw_fd(eventfd.into_raw_fd()) };
    Ok((consumer, notifier))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::{ffi::CString, io::pipe, os::fd::IntoRawFd, process::Command};

    #[test]
    fn test_notify_and_consume() {
        let (reader, writer) = pipe().expect("Failed to create pipe");
        // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
        let notifier = unsafe { EventNotifier::from_raw_fd(writer.into_raw_fd()) };
        // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
        let consumer = unsafe { EventConsumer::from_raw_fd(reader.into_raw_fd()) };

        notifier.notify().unwrap();
        assert!(consumer.consume().is_ok());
    }

    #[test]
    fn test_clone() {
        let (reader, writer) = pipe().expect("Failed to create pipe");
        // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
        let notifier = unsafe { EventNotifier::from_raw_fd(writer.into_raw_fd()) };
        // SAFETY: Safe because we check the fd is valid. And the kernel gave us an fd that we own.
        let consumer = unsafe { EventConsumer::from_raw_fd(reader.into_raw_fd()) };

        let cloned_notifier = notifier.try_clone().expect("Failed to clone notifier");
        let cloned_consumer = consumer.try_clone().expect("Failed to clone consumer");

        cloned_notifier.notify().unwrap();
        assert!(cloned_consumer.consume().is_ok());
    }

    #[test]
    fn test_new_event_notifier_and_consumer() {
        let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::empty())
            .expect("Failed to create notifier and consumer");
        notifier.notify().unwrap();
        assert!(consumer.consume().is_ok());
    }

    #[test]
    fn test_read_nothing() {
        let (consumer, _notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK)
            .expect("Failed to create notifier and consumer");
        let r = consumer.consume();
        match r {
            Err(ref inner) if inner.kind() == io::ErrorKind::WouldBlock => (),
            _ => panic!("Unexpected"),
        }
    }

    #[test]
    fn test_cloexec() {
        let (_consumer, _notifier) = new_event_consumer_and_notifier(EventFlag::CLOEXEC)
            .expect("Failed to create notifier and consumer");

        // SAFETY: This is safe because we are checking the return value is valid.
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let path = CString::new("/bin/sleep").expect("CString::new failed");
                let arg0 = CString::new("sleep").expect("CString::new failed");
                let arg1 = CString::new("1").expect("CString::new failed");
                let ret = libc::execl(
                    path.as_ptr(),
                    arg0.as_ptr(),
                    arg1.as_ptr(),
                    std::ptr::null::<i8>(),
                );
                assert_eq!(ret, 0, "execl failed");
            } else {
                let output = Command::new("lsof")
                    .arg("-p")
                    .arg(pid.to_string())
                    .output()
                    .expect("Failed to execute lsof command");
                output.stdout.lines().for_each(|line| {
                    let line = line.expect("Failed to read line");
                    assert!(!line.contains("PIPE") && !line.contains("eventfd"));
                });
            }
        }
    }
}
