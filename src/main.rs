mod data;

extern crate pnet;

use std::ops::Deref;
use std::{panic, process, thread};
use std::fs;
use std::path::PathBuf;

use structopt::StructOpt;
use either::Either;

use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

use serde::{Serialize, Serializer};

use rouille::Response;

use std::sync::{Mutex, Arc};
use crate::data::{Ipv4StatsKey, Ipv6StatsKey, Stats, StatsKey, update_db};

#[derive(StructOpt, Debug)]
#[structopt(name = "whoisthere")]
struct WitOpt {
    #[structopt(short, long, help = "Network interface whoisthere is sniffing from")]
    interface: String,

    #[structopt(
        short,
        long,
        help = "Statistics http server bind address & port",
        default_value = "127.0.0.1:3648"
    )]
    bind: String,

    #[structopt(
        short,
        long,
        help = "Database file path, default to in-memory database",
        parse(from_os_str),
    )]
    db: Option<PathBuf>,
}

fn read_db(path: &Option<PathBuf>) -> Stats {
    if let Some(p) = path {
        match fs::read_to_string(p) {
            Ok(s) => serde_json::from_str(&s).unwrap(),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    // Create empty json
                    fs::File::create(p).unwrap();
                    Stats::new()
                } else {
                    panic!("Fail to read database: {}", e);
                }
            }
        }
    } else {
        Stats::new()
    }
}

fn save_db(path: &Option<PathBuf>, in_memory: &Stats) {
    if let Some(p) = path {
        match serde_json::to_string(in_memory) {
            Ok(s) => match fs::write(p, s) {
                Ok(_) => (),
                Err(e) => {
                    panic!("Fail to write database: {}", e);
                }
            },
            Err(e) => {
                panic!("Fail to serialize database: {}", e);
            }
        }
    }
}

fn main() {
    let opt = WitOpt::from_args();
    let db = Arc::new(Mutex::new(read_db(&opt.db)));

    // https://stackoverflow.com/questions/35988775/how-can-i-cause-a-panic-on-a-thread-to-immediately-end-the-main-thread
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        process::exit(1);
    }));

    let capdb = db.clone();
    let capture_thread = thread::spawn(move || {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .iter().find(|iface| iface.name == opt.interface)
            .expect("No interfaces found");

        let (_tx, mut rx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type: Only Ethernet is supported"),
            Err(e) => panic!("Error creating channel: {}", e)
        };

        eprintln!("Capturing packets on interface: {}", interface.name);
        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(p) = proc_packet(packet) {
                        update_db(capdb.lock().unwrap(), p);
                        save_db(&opt.db, capdb.lock().unwrap().deref());
                    }
                }
                Err(e) => eprintln!("Error receiving packet: {}", e)
            }
        }
    });

    let httpdb = db.clone();
    let http_thread = thread::spawn(move || {
        eprintln!("HTTP server @ {}", opt.bind);
        rouille::start_server(opt.bind, move |request| {
            eprintln!("{:?}", request);
            Response::json(httpdb.lock().unwrap().deref())
        });
    });

    capture_thread.join().unwrap();
    http_thread.join().unwrap();
}

fn proc_packet(packet: &[u8]) -> Option<(StatsKey, u128)> {
    if let Some(eth_packet) = EthernetPacket::new(packet) {
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 =>
                if let Some(p) = Ipv4Packet::new(eth_packet.payload()) {
                    Some((StatsKey(Either::Left(Ipv4StatsKey { source: p.get_source(), dest: p.get_destination() })),
                          p.get_total_length() as u128))
                } else {
                    eprintln!("Fail to construct Ipv4Packet: packet too small");
                    None
                }
            // No, the fact is they are different fundamentally so no polymorphism here sorry
            EtherTypes::Ipv6 =>
                if let Some(p) = Ipv6Packet::new(eth_packet.payload()) {
                    Some((StatsKey(Either::Right(Ipv6StatsKey { source: p.get_source(), dest: p.get_destination() })),
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
