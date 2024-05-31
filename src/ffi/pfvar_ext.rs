use crate::ffi::pfvar::{pf_addr, pf_state_xport, pfsync_state};
use std::fmt;
use std::net::Ipv4Addr;

impl fmt::Debug for pf_addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { // Unsafe due to accessing union data
            let ip = Ipv4Addr::from(u32::from_be(self.pfa._v4addr.s_addr)); // Assuming big-endian for example
            f.debug_tuple("pf_addr")
             .field(&ip)
             .finish()
        }
    }
}

impl fmt::Debug for pf_state_xport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Unsafe due to direct access to union data
        unsafe {
            f.debug_struct("pf_state_xport")
                .field("port", &self.port) // Display as an example; in real use, ensure it's the correct field
                .field("call_id", &self.call_id) // Similarly, ensure correct usage
                .field("spi", &self.spi) // Displaying all, only one of these would be valid at a time
                .finish()
        }
    }
}


impl fmt::Debug for pfsync_state {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Copy each field out into a properly aligned variable
        let id = self.id;
        let rt_addr = self.rt_addr;
        let unlink_hooks = self.unlink_hooks;
        let rule = self.rule;
        let anchor = self.anchor;
        let nat_rule = self.nat_rule;
        let creation = self.creation;
        let expire = self.expire;
        let packets = self.packets;
        let bytes = self.bytes;
        let creatorid = self.creatorid;
        let tag = self.tag;
        let flowhash = self.flowhash;

        f.debug_struct("pfsync_state")
         .field("id", &id)
         .field("ifname", &self.ifname.iter().map(|&c| c as u8 as char).collect::<String>())
         .field("lan", &self.lan)
         .field("gwy", &self.gwy)
         .field("ext_lan", &self.ext_lan)
         .field("ext_gwy", &self.ext_gwy)
         .field("src", &self.src)
         .field("dst", &self.dst)
         .field("rt_addr", &rt_addr)
         .field("unlink_hooks", &unlink_hooks)
         .field("rule", &rule)
         .field("anchor", &anchor)
         .field("nat_rule", &nat_rule)
         .field("creation", &creation)
         .field("expire", &expire)
         .field("packets", &packets)
         .field("bytes", &bytes)
         .field("creatorid", &creatorid)
         .field("tag", &tag)
         .field("af_lan", &self.af_lan)
         .field("af_gwy", &self.af_gwy)
         .field("proto", &self.proto)
         .field("direction", &self.direction)
         .field("log", &self.log)
         .field("allow_opts", &self.allow_opts)
         .field("timeout", &self.timeout)
         .field("sync_flags", &self.sync_flags)
         .field("updates", &self.updates)
         .field("proto_variant", &self.proto_variant)
         .field("__pad", &self.__pad)
         .field("flowhash", &flowhash)
         .finish()
    }
}