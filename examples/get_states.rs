#[macro_use]
extern crate error_chain;

use pfctl::{PfCtl, ffi::pfvar::pf_addr, ffi::pfvar::pf_state_xport};
use std::net::Ipv4Addr;
use std::convert::TryFrom;

error_chain! {}
quick_main!(test_get_states);

// ALL tcp 120.204.94.42:17832 <- 172.20.10.2:54607       ESTABLISHED:ESTABLISHED
// ALL tcp 172.20.10.2:54607 -> 10.114.73.55:35365 -> 120.204.94.42:17832       ESTABLISHED:ESTABLISHED
// ALL udp 2409:8920:e20:c5b3:c05e:d0ea:4c11:a736[56973] <- 2409:8020:2000::6[53]       NO_TRAFFIC:SINGLE
fn protocol_name(protocol_number: u8) -> &'static str {
    match protocol_number {
        1 => "icmp",
        2 => "igmp",
        6 => "tcp",
        17 => "udp",
        47 => "gre",
        50 => "esp",
        51 => "ah",
        58 => "icmpv6",
        89 => "ospf",
        132 => "sctp",
        _ => "unknown",
    }
}

fn direction(dir: u8) -> &'static str {
    match dir {
        1 => "<-",
        2 => "->",
        _ => "--",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PFTM {
    TcpFirstPacket,
    TcpOpening,
    TcpEstablished,
    TcpClosing,
    TcpFinWait,
    TcpClosed,
    UdpFirstPacket,
    UdpSingle,
    UdpMultiple,
    IcmpFirstPacket,
    IcmpErrorReply,
    Grev1FirstPacket,
    Grev1Initiating,
    Grev1Established,
    EspFirstPacket,
    EspInitiating,
    EspEstablished,
    OtherFirstPacket,
    OtherSingle,
    OtherMultiple,
    Frag,
    Interval,
    AdaptiveStart,
    AdaptiveEnd,
    SrcNode,
    TsDiff,
    Max,
    Purge,
    Unlinked,
}

impl PFTM {
    fn as_str(&self) -> &'static str {
        match *self {
            PFTM::TcpFirstPacket => "FIRST_PACKET",
            PFTM::TcpOpening => "OPENING",
            PFTM::TcpEstablished => "ESTABLISHED",
            PFTM::TcpClosing => "CLOSING",
            PFTM::TcpFinWait => "FIN_WAIT",
            PFTM::TcpClosed => "CLOSED",
            PFTM::UdpFirstPacket => "FIRST_PACKET",
            PFTM::UdpSingle => "SINGLE",
            PFTM::UdpMultiple => "MULTIPLE",
            PFTM::IcmpFirstPacket => "FIRST_PACKET",
            PFTM::IcmpErrorReply => "ERROR_REPLY",
            PFTM::Grev1FirstPacket => "FIRST_PACKET",
            PFTM::Grev1Initiating => "INITIATING",
            PFTM::Grev1Established => "ESTABLISHED",
            PFTM::EspFirstPacket => "FIRST_PACKET",
            PFTM::EspInitiating => "INITIATING",
            PFTM::EspEstablished => "ESTABLISHED",
            PFTM::OtherFirstPacket => "FIRST_PACKET",
            PFTM::OtherSingle => "SINGLE",
            PFTM::OtherMultiple => "MULTIPLE",
            PFTM::Frag => "FRAG",
            PFTM::Interval => "INTERVAL",
            PFTM::AdaptiveStart => "ADAPTIVE_START",
            PFTM::AdaptiveEnd => "ADAPTIVE_END",
            PFTM::SrcNode => "SRC_NODE",
            PFTM::TsDiff => "TS_DIFF",
            PFTM::Max => "MAX",
            PFTM::Purge => "PURGE",
            PFTM::Unlinked => "UNLINKED",
        }
    }
}

impl TryFrom<u8> for PFTM {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(PFTM::TcpFirstPacket),
            1 => Ok(PFTM::TcpOpening),
            2 => Ok(PFTM::TcpEstablished),
            3 => Ok(PFTM::TcpClosing),
            4 => Ok(PFTM::TcpFinWait),
            5 => Ok(PFTM::TcpClosed),
            6 => Ok(PFTM::UdpFirstPacket),
            7 => Ok(PFTM::UdpSingle),
            8 => Ok(PFTM::UdpMultiple),
            9 => Ok(PFTM::IcmpFirstPacket),
            10 => Ok(PFTM::IcmpErrorReply),
            11 => Ok(PFTM::Grev1FirstPacket),
            12 => Ok(PFTM::Grev1Initiating),
            13 => Ok(PFTM::Grev1Established),
            14 => Ok(PFTM::EspFirstPacket),
            15 => Ok(PFTM::EspInitiating),
            16 => Ok(PFTM::EspEstablished),
            17 => Ok(PFTM::OtherFirstPacket),
            18 => Ok(PFTM::OtherSingle),
            19 => Ok(PFTM::OtherMultiple),
            20 => Ok(PFTM::Frag),
            21 => Ok(PFTM::Interval),
            22 => Ok(PFTM::AdaptiveStart),
            23 => Ok(PFTM::AdaptiveEnd),
            24 => Ok(PFTM::SrcNode),
            25 => Ok(PFTM::TsDiff),
            26 => Ok(PFTM::Max),
            27 => Ok(PFTM::Purge),
            28 => Ok(PFTM::Unlinked),
            _ => Err(()),
        }
    }
}

fn get_addr_str(addr: &pf_addr) -> String {
    unsafe { // Unsafe due to accessing union data
        let ip = Ipv4Addr::from(u32::from_be(addr.pfa._v4addr.s_addr)); // Assuming big-endian for example
        return ip.to_string();
    }
}

fn get_port_str(xport: &pf_state_xport) -> String {
    unsafe { // Unsafe due to accessing union data
        if xport.port == 0 {
            return "".to_string();
        }
        return format!(":{}", xport.port);
    }
}

fn test_get_states() -> Result<()> {
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;

    // Retrieve and print the states
    match pf.get_states() {
        Ok(states) => {
            // println!("Number of states: {}", states.len());
            for state in states {
                // println!("State: {:?}", state);
                let ifname = String::from_utf8(state.ifname.iter().map(|&c| c as u8).collect()).unwrap().trim().to_string();
                // let ifname = String::from("ALL");
                let protocol = protocol_name(state.proto);
                let lan_addr = state.lan.addr;
                let lan_xport = state.lan.xport;
                let gwy_addr = state.gwy.addr;
                let gwy_xport = state.gwy.xport;
                let ext_lan_addr = state.ext_lan.addr;
                let ext_lan_xport = state.ext_lan.xport;
                // let ext_gwy_addr = state.ext_gwy.addr;
                // let ext_gwy_xport = state.ext_gwy.xport;

                let mut line = format!("{} {} ", ifname, protocol);

                let lan_addr_str = get_addr_str(&lan_addr);
                let lan_port_str = get_port_str(&lan_xport);
                line.push_str(&format!("{}{} ", lan_addr_str, lan_port_str));
                line.push_str(&format!("{} ", direction(state.direction)));
                
                let gwy_addr_str = get_addr_str(&gwy_addr);
                let gwy_port_str = get_port_str(&gwy_xport);
                if lan_addr_str != gwy_addr_str || lan_port_str != gwy_port_str{
                    line.push_str(&format!("{}{} ", get_addr_str(&gwy_addr), get_port_str(&gwy_xport)));
                    line.push_str(&format!("{} ", direction(state.direction)));
                }
                line.push_str(&format!("{}{} ", get_addr_str(&ext_lan_addr), get_port_str(&ext_lan_xport)));
                // line.push_str(&format!("{:?}:{:?} ", state.ext_gwy.addr, state.ext_gwy.xport.port));
                line.push_str(&format!("      {}:{}", PFTM::try_from(state.src.state).unwrap().as_str(), PFTM::try_from(state.dst.state).unwrap().as_str()));
                println!("{}", line);
                // println!("{:?}", state);
            }
        },
        Err(e) => {
            println!("Failed to get states: {}", e);
        }
    }

    Ok(())
}