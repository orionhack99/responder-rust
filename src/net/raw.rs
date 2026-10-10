//! Optional raw Ethernet (AF_PACKET) transmit/receive channel.
//!
//! The poisoners in this build use ordinary UDP sockets (which is sufficient to observe and
//! answer LLMNR/NBT-NS/mDNS/DNS/DHCP on a shared segment and is far more portable). This
//! wrapper is retained for callers that need true L2 control; the `unsafe` boundary of the
//! project is confined to the `pnet` datalink/socket calls used here.

#![allow(dead_code)]

use pnet::datalink::{self, Channel, Config, NetworkInterface};

/// Boxed frame-transmit closure captured by [`RawChannel`].
type TxFn = Box<dyn FnMut(&[u8])>;

/// An opened raw datalink channel for one interface.
pub struct RawChannel {
    tx: TxFn,
    _rx: Option<()>,
}
impl RawChannel {
    /// Open a raw datalink channel for `iface`, sending any frame given to [`RawChannel::send`].
    pub fn open(iface: &NetworkInterface) -> anyhow::Result<Self> {
        #[allow(unused_mut)]
        let (mut tx, mut rx) = match datalink::channel(iface, Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => anyhow::bail!("unsupported datalink channel type"),
            Err(e) => anyhow::bail!("failed to open datalink channel: {e}"),
        };
        // Drain incoming frames on a background thread; callers that need to react to traffic
        // should use the UDP-based poisoners instead.
        std::thread::spawn(move || {
            loop {
                let _ = rx.next();
            }
        });
        Ok(RawChannel {
            tx: Box::new(move |buf: &[u8]| {
                let _ = tx.send_to(buf, None);
            }),
            _rx: None,
        })
    }

    pub fn send(&mut self, frame: &[u8]) {
        (self.tx)(frame);
    }
}
