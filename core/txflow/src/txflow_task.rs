use futures::sync::mpsc;
use futures::{Future, Poll, Async, Stream, stream};

use primitives::types::{UID, Gossip};
use primitives::traits::{Payload, WitnessSelector};
use dag::DAG;

// A single message can be 
// 1) received message in a gossip, if has unknown parents:

/// A future that owns TxFlow DAG and encapsulates gossiping logic. Should be run as a separate
/// task by a reactor. Consumes a stream of gossips and payloads, and produces a stream of gossips
/// and consensuses. Currently produces only stream of gossips, TODO stream of consensuses.
pub struct TxFlowTask<'a, P: Payload, W: WitnessSelector> {
    owner_uid: UID,
    starting_epoch: u64,
    messages_receiver: mpsc::Receiver<Gossip<P>>,
    payload_receiver: mpsc::Receiver<P>,
    messages_sender: mpsc::Sender<Gossip<P>>,
    witness_selector: Box<W>,
    dag: Option<Box<DAG<'a, P, W>>>,
}

impl<'a, P: Payload, W: WitnessSelector> TxFlowTask<'a, P, W> {
    pub fn new(owner_uid: UID,
           starting_epoch: u64,
           messages_receiver: mpsc::Receiver<Gossip<P>>,
           payload_receiver: mpsc::Receiver<P>,
           messages_sender: mpsc::Sender<Gossip<P>>,
           witness_selector: W) -> Self {
        Self {
            owner_uid,
            starting_epoch,
            messages_receiver,
            payload_receiver,
            messages_sender,
            witness_selector: Box::new(witness_selector),
            dag: None,
        }
    }
}

impl<'a, P: Payload, W: WitnessSelector> Future for TxFlowTask<'a, P, W> {
    // This stream does not produce anything, it is meant to be run as a standalone task.
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Check if DAG needs to be created.
        if self.dag.is_none() {
            let witness_ptr = self.witness_selector.as_ref() as *const W;
            // Since we are controlling the creation of the DAG by encapsulating it here
            // this code is safe.
            self.dag = Some(Box::new(
                DAG::new(self.owner_uid, self.starting_epoch, unsafe {&*witness_ptr})));
        }

        loop {
            let res = self.messages_receiver.poll();
            let incoming_gossip = match res {
                Ok(Async::Ready(Some(gossip))) => gossip,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(None)) => break,
                _ => break,
            };
            //self.messages_sender.send(incoming_gossip);
        }
        Ok(Async::Ready(()))
    }
}


#[cfg(test)]
mod tests {
    use tokio;

    use futures::sync::mpsc;
    use primitives::types::{UID, Gossip};
    use primitives::traits::WitnessSelector;
    use std::collections::{HashSet, HashMap};
    use futures::{Future, Poll, Async, Stream, Sink, stream};
    use futures::future::lazy;
    use rand::{thread_rng, Rng};

    use super::TxFlowTask;
    use testing_utils::FakePayload;

    struct FakeWitnessSelector {
        schedule: HashMap<u64, HashSet<UID>>,
    }

    impl FakeWitnessSelector {
        fn new() -> FakeWitnessSelector {
            FakeWitnessSelector {
                schedule: map!{
               0 => set!{0, 1, 2, 3}, 1 => set!{1, 2, 3, 4},
               2 => set!{2, 3, 4, 5}, 3 => set!{3, 4, 5, 6}}
            }
        }
    }

    impl WitnessSelector for FakeWitnessSelector {
        fn epoch_witnesses(&self, epoch: u64) -> &HashSet<u64> {
            self.schedule.get(&epoch).unwrap()
        }
        fn epoch_leader(&self, epoch: u64) -> UID {
            *self.epoch_witnesses(epoch).iter().min().unwrap()
        }
    }

    #[test]
    fn tmp() {
        return;
        let selector = FakeWitnessSelector::new();
        let (inc_gossip_tx, inc_gossip_rx) = mpsc::channel::<Gossip<FakePayload>>(1024);
        let (inc_payload_tx, inc_payload_rx) = mpsc::channel::<FakePayload>(1024);
        let (out_gossip_tx, out_gossip_rx) = mpsc::channel::<Gossip<FakePayload>>(1024);
        let task = TxFlowTask::new(0,0, inc_gossip_rx, inc_payload_rx, out_gossip_tx, selector);
        tokio::run(task);
    }

    fn print_type_of<T>(_: &T) {
        println!("{}", unsafe { std::intrinsics::type_name::<T>() });
    }


    use tokio::io;

    fn accumulator() {
        tokio::run(lazy(|| {
            let (inc_tx, inc_rx) = mpsc::channel(1_024);
            let (out_tx, out_rx) = mpsc::channel(1_024);



            tokio::spawn({
                stream::iter_ok(0..10).fold(inc_tx, |x, i| {
                    let tmp = x.send(format!("Emitted {}", i));

                    print_type_of(&tmp);
                    tmp.map_err(|e| println!("error = {:?}", e))
                })
                    .map(|_| ()) // Drop tx handle
            });

            tokio::spawn({
                inc_rx.fold(out_tx, |out_tx, m| {
                    out_tx.send(format!("Relayed `{}`", m))
                        .map_err(|e| println!("error = {:?}", e))
                }).map(|_| ())
            });


            tokio::spawn(
            out_rx.for_each(|msg| {
                println!("Finally `{}`", msg);
                Ok(())
            }));

            Ok(())
        }));
    }
    use std::time::Duration;
    use tokio::timer::Delay;

    pub const COOLDOWN: u64 = 1000;
    pub const FORCED_PING: u64 = 1500;

    struct Accumulator {
        acc: i64,
        inc_rx: mpsc::Receiver<i64>,
        out_tx: mpsc::Sender<i64>,
        cooldown_delay: Option<Delay>,
        forced_ping_delay: Option<Delay>,
    }

    impl Accumulator {
        pub fn new(acc: i64, inc_rx: mpsc::Receiver<i64>, out_tx: mpsc::Sender<i64>) -> Self {
            Self {
                acc,
                inc_rx,
                out_tx,
                cooldown_delay: None,
                forced_ping_delay: None,
            }
        }
    }

    impl Stream for Accumulator {
        type Item = ();
        type Error = ();
        fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
            let value = match self.inc_rx.poll() {
                Ok(Async::Ready(Some(value))) => value,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(None)) => return Ok(Async::Ready(None)),
                Err(_) => return Err(()),
            };
            self.acc += value;
            let copied_out_tx = self.out_tx.clone();
            match copied_out_tx.send(self.acc).poll() {
                Ok(Async::Ready(_)) => Ok(Async::Ready(Some(()))),
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Err(_) => {
                    println!("Receiver of Accumulator output was already deallocated");
                    Err(())
                },
            }
        }
    }

    impl Future for Accumulator {
        type Item = ();
        type Error = ();
        fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
            try_ready!(
             (self as &mut Stream<Item=Self::Item, Error=Self::Error>)
            .for_each(|_| Ok(())).poll());
            Ok(Async::Ready(()))
        }
    }

    #[test]
    fn my_accumulator() {
        tokio::run(lazy(|| {
            let (inc_tx, inc_rx) = mpsc::channel(1_024);
            let (out_tx, out_rx) = mpsc::channel(1_024);
            let mut acc = Accumulator::new(0, inc_rx, out_tx);
            tokio::spawn({
                let mut v: Vec<i64> = vec![];
                for i in 0..10 {
                    let r: i64 = rand::random();
                    v.push(r.abs() % 10);
                }
                stream::iter_ok(v).fold(inc_tx, |inc_tx, el| {
                    println!("Sending {}", el);
                    inc_tx.send(el).map_err(|_| ())
                }).map(|_|())
            });

            tokio::spawn(
                out_rx.for_each(|el| {
                    println!("Received {}", el);
                    Ok(())
                })
            );
            tokio::spawn(acc);
            Ok(())
        }));
    }

}