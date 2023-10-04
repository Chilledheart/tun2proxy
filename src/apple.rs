#![cfg(any(target_os = "ios", target_os = "macos"))]

use smoltcp::{
    phy::{self, Device, DeviceCapabilities, Medium},
    time::Instant,
};
use std::{
    cell::RefCell,
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
};

/// A socket that captures or transmits the complete frame.
#[derive(Debug)]
pub struct AppleInterface {
    medium: Medium,
    lower: Rc<RefCell<AppleInterfaceDesc>>,
    mtu: usize,
    old_gateway: Option<IpAddr>,
}

impl std::os::fd::AsRawFd for AppleInterface {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.lower.borrow().as_raw_fd()
    }
}

impl AppleInterface {
    /// Creates a utun socket, bound to the interface called `name`.
    ///
    /// This requires superuser privileges or a corresponding capability bit
    /// set on the executable.
    pub fn new(name: &str, medium: Medium) -> std::io::Result<AppleInterface> {
        let lower = AppleInterfaceDesc::new(name, medium)?;
        let mtu = lower.interface_mtu()?;
        Ok(AppleInterface {
            medium,
            lower: Rc::new(RefCell::new(lower)),
            mtu,
            old_gateway: None,
        })
    }

    /// Attaches to a TUN interface specified by file descriptor `fd`.
    ///
    /// On platforms like iOS, a file descriptor to a tun interface is exposed.
    /// On these platforms, a AppleInterface cannot be instantiated with a name.
    pub fn from_fd(fd: std::os::fd::RawFd, medium: Medium) -> std::io::Result<AppleInterface> {
        use std::os::fd::FromRawFd;
        let lower = unsafe { AppleInterfaceDesc::from_raw_fd(fd) };
        let mtu = lower.interface_mtu()?;
        Ok(AppleInterface {
            medium,
            lower: Rc::new(RefCell::new(lower)),
            mtu,
            old_gateway: None,
        })
    }
}

impl Device for AppleInterface {
    type RxToken<'a> = RxToken
    where
        Self: 'a;
    type TxToken<'a> = TxToken
    where
        Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut v = DeviceCapabilities::default();
        v.max_transmission_unit = self.mtu;
        v.medium = self.medium;
        v
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buffer = vec![0; self.mtu];
        match self.lower.borrow_mut().recv(&mut buffer[..]) {
            Ok(size) => {
                buffer.resize(size, 0);
                let rx = RxToken { buffer };
                let tx = TxToken {
                    lower: self.lower.clone(),
                };
                Some((rx, tx))
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(err) => panic!("{}", err),
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            lower: self.lower.clone(),
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..])
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<AppleInterfaceDesc>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        match self.lower.borrow_mut().send(&buffer[..]) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                log::trace!("phy: tx failed due to WouldBlock")
            }
            Err(err) => panic!("{}", err),
        }
        result
    }
}

#[derive(Debug)]
pub struct AppleInterfaceDesc {
    fd: libc::c_int,
    name: String,
}

impl std::os::fd::AsRawFd for AppleInterfaceDesc {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd
    }
}

impl std::os::fd::FromRawFd for AppleInterfaceDesc {
    unsafe fn from_raw_fd(fd: std::os::fd::RawFd) -> AppleInterfaceDesc {
        let name = get_tun_name(fd).unwrap_or("utun0-error".to_string());
        AppleInterfaceDesc { fd, name }
    }
}

impl AppleInterfaceDesc {
    pub fn new(_name: &str, _medium: Medium) -> std::io::Result<AppleInterfaceDesc> {
        let (fd, name) = open_utun_socket()?;
        Ok(AppleInterfaceDesc { fd, name })
    }

    pub fn interface_mtu(&self) -> std::io::Result<usize> {
        let mtu = get_tun_mtu(&self.name)?;
        log::trace!("\"{}\" mtu {}", self.name, mtu);
        Ok(mtu as usize)
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let len = libc::read(self.fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
            if len == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        unsafe {
            let len = libc::write(self.fd, buffer.as_ptr() as *const libc::c_void, buffer.len());
            if len == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }
}

impl Drop for AppleInterfaceDesc {
    fn drop(&mut self) {
        log::trace!("closing utun device \"{}\"", self.name);
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

fn fd_failed_return<T>(fd: libc::c_int) -> std::io::Result<T> {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    Err(std::io::Error::last_os_error())
}

/// Open a TUN device on macOS.
/// Reference from [here](https://stackoverflow.com/questions/56003563/how-to-create-virtual-interface-in-macos).
/// Return the file descriptor and name of the TUN device.
pub fn open_utun_socket() -> std::io::Result<(std::os::fd::RawFd, String)> {
    use std::os::fd::RawFd;

    const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

    let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };

    let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return fd_failed_return(fd);
    }

    UTUN_CONTROL_NAME
        .as_bytes()
        .iter()
        .zip(info.ctl_name.iter_mut())
        .for_each(|(a, b)| *b = *a as libc::c_char);

    if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } != 0 {
        return fd_failed_return(fd);
    }

    addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as libc::c_uchar;
    addr.sc_family = libc::AF_SYSTEM as libc::sa_family_t;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as libc::c_ushort;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // create new interface if sc_unit == 0

    let p = &addr as *const libc::sockaddr_ctl as *const libc::sockaddr;
    let err = unsafe { libc::connect(fd, p, std::mem::size_of_val(&addr) as libc::socklen_t) };
    if err != 0 {
        return fd_failed_return(fd);
    }

    let ifname_str = get_tun_name(fd)?;

    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
        return fd_failed_return(fd);
    }

    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return fd_failed_return(fd);
    }

    Ok((RawFd::from(fd), ifname_str.to_string()))
}

pub fn get_tun_name(fd: std::os::fd::RawFd) -> std::io::Result<String> {
    const UTUN_OPT_IFNAME: libc::c_int = 2;

    let mut ifname: [libc::c_char; libc::IFNAMSIZ] = unsafe { std::mem::zeroed() };
    let mut ifname_len = std::mem::size_of_val(&ifname) as libc::socklen_t;

    // Forward ifname (we just expect it to be utun0 for now...)
    let p = ifname.as_mut_ptr() as *mut _;
    let err = unsafe { libc::getsockopt(fd, libc::SYSPROTO_CONTROL, UTUN_OPT_IFNAME, p, &mut ifname_len) };
    if err != 0 {
        return fd_failed_return(fd);
    }

    let ifname_slice = unsafe { std::slice::from_raw_parts(ifname.as_ptr() as *const u8, ifname_len as usize - 1) };
    let ifname_str = String::from_utf8_lossy(ifname_slice);
    log::trace!("utun name \"{}\"", ifname_str);
    Ok(ifname_str.to_string())
}

pub fn get_tun_mtu(tun: &str) -> std::io::Result<usize> {
    let mut mib: [i32; 6] = [0; 6];
    let mut len: usize = std::mem::size_of::<i32>();

    let tun = std::ffi::CString::new(tun).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    mib[0] = libc::CTL_NET;
    mib[1] = libc::PF_ROUTE;
    mib[4] = libc::NET_RT_IFLIST;
    mib[5] = unsafe { libc::if_nametoindex(tun.as_ptr()) } as i32;

    let null = std::ptr::null_mut::<libc::c_void>();

    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, null, &mut len, null, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let buf = vec![0u8; len];
    let buf_ptr = buf.as_ptr() as *mut libc::c_void;

    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, buf_ptr, &mut len, null, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let lim = unsafe { buf_ptr.add(len) };
    let mut next = buf_ptr;

    loop {
        let rtm = unsafe { &mut *(next as *mut libc::if_msghdr) };
        if rtm.ifm_type as libc::c_int == libc::RTM_IFINFO {
            return Ok(rtm.ifm_data.ifi_mtu as usize);
        }

        next = unsafe { next.offset(rtm.ifm_msglen as isize) };
        if next >= lim {
            break;
        }
    }

    Err(std::io::Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn get_active_gateway() -> std::io::Result<Ipv4Addr> {
    // Command: `netstat -rn | grep default | grep -E -o "[0-9\.]+" | head -n 1`
    let output = run_command("netstat", &["-rn"])?;
    let output_str = String::from_utf8_lossy(&output);
    let gateway = output_str
        .lines()
        .filter(|line| line.contains("default"))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                Some(parts[1])
            } else {
                None
            }
        })
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .next();
    use std::io::ErrorKind::Other;
    let err = "Failed to parse default gateway from \"netstat\" output";
    gateway.ok_or(std::io::Error::new(Other, err))
}

#[cfg(target_os = "macos")]
pub(crate) fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("{} failed with: \"{}\"", command, err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

impl AppleInterface {
    #[cfg(target_os = "ios")]
    pub fn setup_config(&mut self, _bypass_ip: Option<IpAddr>, _dns_addr: Option<IpAddr>) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn setup_config(&mut self, bypass_ip: Option<IpAddr>, dns: Option<IpAddr>) -> std::io::Result<()> {
        let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

        // 0. Save the old gateway
        let old_gateway = get_active_gateway()?;
        self.old_gateway = Some(old_gateway.into());

        // 1. Set up the address and netmask and gateway of the interface
        // Command: `sudo ifconfig tun_name 10.0.0.33 10.0.0.1 netmask 255.255.255.0`
        let tun_name = self.lower.borrow().name.clone();
        let args = &[
            "ifconfig",
            &tun_name,
            "10.0.0.33",
            "10.0.0.1",
            "netmask",
            "255.255.255.0",
        ];
        run_command("sudo", args)?;

        // 2. Remove the default route
        // Command: `sudo route delete 0.0.0.0`
        let args = &["route", "delete", &unspecified];
        run_command("sudo", args)?;

        // 3. Set the gateway `10.0.0.1` as the default route
        // Command: `sudo route add -net 0.0.0.0 10.0.0.1`
        let args = &["route", "add", "-net", &unspecified, "10.0.0.1"];
        run_command("sudo", args)?;

        // 4. Route the bypass ip to the old gateway
        // Command: `sudo route add bypass_ip/32 old_gateway`
        let bypass_ip = bypass_ip.unwrap_or(Ipv4Addr::LOCALHOST.into()).to_string();
        let args = &["route", "add", &bypass_ip, &old_gateway.to_string()];
        run_command("sudo", args)?;

        // 5. Set the DNS server to a reserved IP address
        // Command: `sudo sh -c "echo nameserver 198.18.0.1 > /etc/resolv.conf"`
        let dns = dns.unwrap_or("198.18.0.1".parse::<IpAddr>().unwrap()).to_string();
        let content = format!("nameserver {}\n", &dns);
        let f = std::fs::File::create("/etc/resolv.conf")?;
        let mut f = std::io::BufWriter::new(f);
        use std::io::Write;
        f.write_all(content.as_bytes())?;
        f.flush()?;

        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn restore_config(&mut self) -> Result<(), std::io::Error> {
        if self.old_gateway.is_none() {
            return Ok(());
        }
        let unspecified = Ipv4Addr::UNSPECIFIED.to_string();

        // 1. Remove current adapter's route
        // command: `sudo route delete 0.0.0.0`
        let args = &["route", "delete", &unspecified];
        run_command("sudo", args)?;

        // 2. Add back the old gateway route
        // command: `sudo route add -net 0.0.0.0 old_gateway`
        let old_gateway = self.old_gateway.take().unwrap().to_string();
        let args = &["route", "add", "-net", &unspecified, &old_gateway];
        run_command("sudo", args)?;

        // 3. Restore DNS server to the old gateway
        // command: `sudo sh -c "echo nameserver old_gateway > /etc/resolv.conf"`
        let content = format!("nameserver {}\n", &old_gateway);
        let f = std::fs::File::create("/etc/resolv.conf")?;
        let mut f = std::io::BufWriter::new(f);
        use std::io::Write;
        f.write_all(content.as_bytes())?;
        f.flush()?;

        Ok(())
    }
}

impl Drop for AppleInterface {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Err(e) = self.restore_config() {
            log::error!("Failed to restore the network config: {}", e);
        }
    }
}
