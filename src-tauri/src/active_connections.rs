use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ActiveConnection {
    pub protocol: &'static str,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    pub pid: u32,
    pub app_path: Option<String>,
    pub app_name: String,
}

#[cfg(windows)]
mod imp {
    use super::ActiveConnection;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn snapshot() -> Vec<ActiveConnection> {
        let mut cache = HashMap::new();
        let mut out = Vec::new();
        out.extend(tcp4(&mut cache));
        out.extend(tcp6(&mut cache));
        out.extend(udp4(&mut cache));
        out.extend(udp6(&mut cache));
        out
    }

    fn process_info(
        cache: &mut HashMap<u32, (Option<String>, String)>,
        pid: u32,
    ) -> (Option<String>, String) {
        if let Some(info) = cache.get(&pid) {
            return info.clone();
        }
        let path = process_path(pid);
        let name = path.as_deref().map(app_name).unwrap_or_else(|| match pid {
            0 => "System Idle".to_string(),
            4 => "System".to_string(),
            _ => format!("pid {pid}"),
        });
        cache.insert(pid, (path.clone(), name.clone()));
        (path, name)
    }

    fn process_path(pid: u32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        let _ = unsafe { CloseHandle(handle) };
        result.ok()?;
        if len == 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    fn app_name(path: &str) -> String {
        path.rsplit(['\\', '/'])
            .find(|part| !part.is_empty())
            .unwrap_or(path)
            .to_string()
    }

    fn port(value: u32) -> u16 {
        u16::from_be((value & 0xffff) as u16)
    }

    fn v4(value: u32) -> Ipv4Addr {
        Ipv4Addr::from(value.to_ne_bytes())
    }

    fn is_unspecified(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }

    fn aligned_buffer(size: u32) -> Vec<usize> {
        let word = std::mem::size_of::<usize>();
        vec![0; (size as usize).div_ceil(word)]
    }

    fn tcp4(cache: &mut HashMap<u32, (Option<String>, String)>) -> Vec<ActiveConnection> {
        let mut size = 0u32;
        let err = unsafe {
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if err != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
            return Vec::new();
        }
        let mut buf = aligned_buffer(size);
        let err = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if err != ERROR_SUCCESS.0 {
            return Vec::new();
        }
        let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let count = unsafe { (*table).dwNumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };
        rows.iter()
            .filter_map(|row: &MIB_TCPROW_OWNER_PID| {
                let remote_ip = IpAddr::V4(v4(row.dwRemoteAddr));
                if is_unspecified(&remote_ip) {
                    return None;
                }
                let (app_path, app_name) = process_info(cache, row.dwOwningPid);
                Some(ActiveConnection {
                    protocol: "tcp",
                    remote_ip,
                    remote_port: port(row.dwRemotePort),
                    local_port: port(row.dwLocalPort),
                    pid: row.dwOwningPid,
                    app_path,
                    app_name,
                })
            })
            .collect()
    }

    fn tcp6(cache: &mut HashMap<u32, (Option<String>, String)>) -> Vec<ActiveConnection> {
        let mut size = 0u32;
        let err = unsafe {
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if err != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
            return Vec::new();
        }
        let mut buf = aligned_buffer(size);
        let err = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if err != ERROR_SUCCESS.0 {
            return Vec::new();
        }
        let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
        let count = unsafe { (*table).dwNumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };
        rows.iter()
            .filter_map(|row: &MIB_TCP6ROW_OWNER_PID| {
                let remote_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
                if is_unspecified(&remote_ip) {
                    return None;
                }
                let (app_path, app_name) = process_info(cache, row.dwOwningPid);
                Some(ActiveConnection {
                    protocol: "tcp",
                    remote_ip,
                    remote_port: port(row.dwRemotePort),
                    local_port: port(row.dwLocalPort),
                    pid: row.dwOwningPid,
                    app_path,
                    app_name,
                })
            })
            .collect()
    }

    fn udp4(cache: &mut HashMap<u32, (Option<String>, String)>) -> Vec<ActiveConnection> {
        let mut size = 0u32;
        let err = unsafe {
            GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if err != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
            return Vec::new();
        }
        let mut buf = aligned_buffer(size);
        let err = unsafe {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if err != ERROR_SUCCESS.0 {
            return Vec::new();
        }
        let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
        let count = unsafe { (*table).dwNumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };
        rows.iter()
            .map(|row: &MIB_UDPROW_OWNER_PID| {
                let (app_path, app_name) = process_info(cache, row.dwOwningPid);
                ActiveConnection {
                    protocol: "udp",
                    remote_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    remote_port: 0,
                    local_port: port(row.dwLocalPort),
                    pid: row.dwOwningPid,
                    app_path,
                    app_name,
                }
            })
            .collect()
    }

    fn udp6(cache: &mut HashMap<u32, (Option<String>, String)>) -> Vec<ActiveConnection> {
        let mut size = 0u32;
        let err = unsafe {
            GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if err != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
            return Vec::new();
        }
        let mut buf = aligned_buffer(size);
        let err = unsafe {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if err != ERROR_SUCCESS.0 {
            return Vec::new();
        }
        let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
        let count = unsafe { (*table).dwNumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };
        rows.iter()
            .map(|row: &MIB_UDP6ROW_OWNER_PID| {
                let (app_path, app_name) = process_info(cache, row.dwOwningPid);
                ActiveConnection {
                    protocol: "udp",
                    remote_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    remote_port: 0,
                    local_port: port(row.dwLocalPort),
                    pid: row.dwOwningPid,
                    app_path,
                    app_name,
                }
            })
            .collect()
    }
}

#[cfg(not(windows))]
mod imp {
    use super::ActiveConnection;

    pub fn snapshot() -> Vec<ActiveConnection> {
        Vec::new()
    }
}

pub fn snapshot() -> Vec<ActiveConnection> {
    imp::snapshot()
}
