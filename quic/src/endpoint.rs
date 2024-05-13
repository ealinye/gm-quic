use crate::{connection::Connection, ReceiveProtectedPacket};
use qbase::{
    cid::ConnectionId,
    packet::{GetDcid, ProtectedPacket},
};
use std::collections::HashMap;

pub struct Endpiont {
    // 尚未实现连接迁移，多个连接id对应一个连接的功能尚未实现
    connections: HashMap<ConnectionId, Connection>,
    // 新连接的监听器
    // listener: Listener,
}

impl ReceiveProtectedPacket for Endpiont {
    fn receive_protected_packet(&mut self, protected_packet: ProtectedPacket) {
        let dcid = protected_packet.get_dcid();
        if let Some(conn) = self.connections.get_mut(dcid) {
            // let _ = conn.receive_protected_packet(protected_packet);
        } else {
            match protected_packet {
                ProtectedPacket::Initial(packet) => {
                    // TODO: 创建新连接，并塞给Listener
                }
                _other => {
                    // just ignore
                }
            }
        }
    }
}