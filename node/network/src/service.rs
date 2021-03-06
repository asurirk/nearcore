use futures::{stream, Future, Stream};
use primitives::traits::{Block, Header as BlockHeader, Encode};
use protocol::{self, Protocol, ProtocolConfig};
use std::sync::Arc;
use parking_lot::Mutex;
use std::time::Duration;
pub use substrate_network_libp2p::NetworkConfiguration;
use message::Message;
use substrate_network_libp2p::{
    start_service, RegisteredProtocol, Service as NetworkService, ServiceEvent, Severity, NodeIndex
};
use tokio::timer::Interval;
use futures::sync::mpsc::Receiver;

const TICK_TIMEOUT: Duration = Duration::from_millis(1000);

pub fn new_network_service(protocol_config: &ProtocolConfig, net_config: NetworkConfiguration) -> NetworkService {
    let version = [protocol::CURRENT_VERSION as u8];
    let registered = RegisteredProtocol::new(protocol_config.protocol_id, &version);
    start_service(net_config, Some(registered))
        .expect("Error starting network service")
}

pub fn create_network_task<B, Header>(
    network_service: Arc<Mutex<NetworkService>>,
    protocol_: Protocol<B, Header>,
    message_receiver: Receiver<(NodeIndex, Message<B, Header>)>
) -> (Box<impl Future<Item=(), Error=()>>,
      Box<impl Future<Item=(), Error=()>>)
where
    B: Block,
    Header: BlockHeader,
{
    let protocol = Arc::new(protocol_);
    // Interval for performing maintenance on the protocol handler.
    let timer = Interval::new_interval(TICK_TIMEOUT)
        .for_each({
            let network_service1 = network_service.clone();
            let protocol1 = protocol.clone();
            move |_| {
                for timed_out in protocol1.maintain_peers() {
                    error!("Dropping timeouted node {:?}.", timed_out);
                    network_service1.lock().drop_node(timed_out);
                }
                Ok(())
            }
        }).then(|res| {
            match res {
                Ok(()) => (),
                Err(err) => error!("Error in the propagation timer: {:?}", err),
            };
            Ok(())
        }).map(|_| ()).map_err(|_: ()| ());

    // Handles messages coming from the network.
    let network = stream::poll_fn({
        let network_service1 = network_service.clone();
        move || network_service1.lock().poll()
    }).for_each({
        let network_service1 = network_service.clone();
        let protocol1 = protocol.clone();
        move |event| {
            debug!(target: "sub-libp2p", "event: {:?}", event);
            match event {
                ServiceEvent::CustomMessage { node_index, data, .. } => {
                    if let Err((node_index, severity))
                    = protocol1.on_message(node_index, &data) {
                        match severity {
                            Severity::Bad(err) => {
                                error!("Banning bad node {:?}. {:?}", node_index, err);
                                network_service1.lock().ban_node(node_index);
                            },
                            Severity::Useless(err) => {
                                error!("Dropping useless node {:?}. {:?}", node_index, err);
                                network_service1.lock().drop_node(node_index);
                            },
                            Severity::Timeout => {
                                error!("Dropping timeouted node {:?}.", node_index);
                                network_service1.lock().drop_node(node_index);
                            }
                        }
                    }
                }
                ServiceEvent::OpenedCustomProtocol { node_index, .. } => {
                    protocol1.on_peer_connected(node_index);
                }
                ServiceEvent::ClosedCustomProtocol { node_index, .. } => {
                    protocol1.on_peer_disconnected(node_index);
                }
                _ => {
                    debug!("TODO");
                }
            };
            Ok(())
        }
    }).map(|_| ()).map_err(|_|());

    // Handles messages going into the network.
    let protocol_id = protocol.config.protocol_id;
    let messages_handler = message_receiver.for_each(move |(node_index, m)| {
        let data = Encode::encode(&m).expect("Error encoding message.");
        let cloned = network_service.clone();
        cloned.lock().send_custom_message(node_index, protocol_id, data);
        Ok(())
    }).map(|_| ()).map_err(|_|());



    (Box::new(network.select(timer).and_then(|_| {
        info!("Networking stopped");
        Ok(())
    }).map_err(|(e, _)| debug!("Networking/Maintenance error {:?}", e))),
     Box::new(messages_handler))
}

//#[cfg(test)]
//mod tests {
//    use super::*;
//    use std::time::Instant;
//    use test_utils::*;
//    use tokio::timer::Delay;
//
//    #[test]
//    fn test_send_message() {
//        let services = create_test_services(2);
//        let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
//        for service in services.iter() {
//            let task = generate_service_task::<MockBlock, MockProtocolHandler, MockBlockHeader>(
//                &service.network,
//                &service.protocol,
//            );
//            runtime.spawn(task);
//        }
//
//        let when = Instant::now() + Duration::from_millis(1000);
//        let send_messages =
//            Delay::new(when).map_err(|e| panic!("timer failed; err={:?}", e)).and_then(move |_| {
//                for service in services.iter() {
//                    for peer in service.protocol.sample_peers(1).unwrap() {
//                        let message = fake_tx_message();
//                        let mut net_sync = NetSyncIo::new(
//                            service.network.clone(),
//                            service.protocol.config.protocol_id,
//                        );
//                        service.protocol.send_message(&mut net_sync, peer, &message);
//                    }
//                }
//                Ok(())
//            });
//        runtime.block_on(send_messages).unwrap();
//    }
//}
