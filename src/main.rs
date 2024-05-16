extern crate pnet;

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use structopt::StructOpt;
use either::{Either, Left, Right};

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

use std::sync::{Mutex, Arc, MutexGuard};

#[derive(StructOpt, Debug)]
#[structopt(name = "whoisthere")]
struct WitOpt {
    #[structopt(short, long)]
    interface: String,
}

fn main() {
    let opt = WitOpt::from_args();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter().find(|iface| iface.name == opt.interface)
        .expect("No interfaces found");

    let (_tx, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type: Only Ethernet is supported"),
        Err(e) => panic!("Error creating channel: {}", e)
    };

    let db = Arc::new(Mutex::new(Stats::new()));

    println!("Capturing packets on interface: {}", interface.name);
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(p) = proc_packet(packet) {
                    update_db(Arc::clone(&db).lock().unwrap(), p);
                    println!("{}\n", Arc::clone(&db).lock().unwrap());
                }
            }
            Err(e) => eprintln!("Error receiving packet: {}", e)
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
struct Ipv4StatsKey {
    pub source: Ipv4Addr,
    pub dest: Ipv4Addr,
}

#[derive(PartialEq, Eq, Hash)]
struct Ipv6StatsKey {
    pub source: Ipv6Addr,
    pub dest: Ipv6Addr,
}

// E0117 was in my way so workaround ╮( ╯_╰)╭
#[derive(PartialEq, Eq, Hash)]
struct StatsKey(Either<Ipv4StatsKey, Ipv6StatsKey>);

struct StatsValue {
    pub total_length: u128,
    pub total_count: u128,
}

// Stupid E0117
struct Stats(HashMap<StatsKey, StatsValue>);

impl Stats {
    fn new() -> Self {
        Stats(HashMap::new())
    }
}

impl StatsValue {
    fn new() -> Self {
        StatsValue { total_length: 0, total_count: 0 }
    }
}

impl Display for StatsKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Left(v4) => write!(f, "{} -> {}", v4.source, v4.dest),
            Right(v6) => write!(f, "{} -> {}", v6.source, v6.dest)
        }
    }
}

impl Display for StatsValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "count : {} size : {}", self.total_count, self.total_length)
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.iter()
            .map(|(k, v)| writeln!(f, "{} --- {}", k, v))
            .try_fold((), |_, result| result)
    }
}

type Db = Arc<Mutex<Stats>>;

fn proc_packet(packet: &[u8]) -> Option<(StatsKey, u128)> {
    if let Some(eth_packet) = EthernetPacket::new(packet) {
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 =>
                if let Some(p) = Ipv4Packet::new(eth_packet.payload()) {
                    Some((StatsKey(Left(Ipv4StatsKey { source: p.get_source(), dest: p.get_destination() })),
                          p.get_total_length() as u128))
                } else {
                    eprintln!("Fail to construct Ipv4Packet: packet too small");
                    None
                }
            // No, the fact is they are different fundamentally so no polymorphism here sorry
            EtherTypes::Ipv6 =>
                if let Some(p) = Ipv6Packet::new(eth_packet.payload()) {
                    Some((StatsKey(Right(Ipv6StatsKey { source: p.get_source(), dest: p.get_destination() })),
                          p.get_payload_length() as u128))
                } else {
                    eprintln!("Fail to construct Ipv6Packet: packet too small");
                    None
                }
            _ => {
                eprintln!("Not a IPv4 or IPv6 packet");
                None
            }
        }
    } else {
        eprintln!("Fail to construct EthernetPacket: packet too small");
        None
    }
}

fn update_db(mut unlocked_db: MutexGuard<Stats>, stats: (StatsKey, u128)) {
    let unlocked_db = &mut unlocked_db.0;
    let entry = unlocked_db.entry(stats.0).or_insert(StatsValue::new());
    entry.total_count += 1;
    entry.total_length += stats.1;
}
