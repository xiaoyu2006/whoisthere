use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::MutexGuard;
use either::Either;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(PartialEq, Eq, Hash)]
pub struct Ipv4StatsKey {
    pub source: Ipv4Addr,
    pub dest: Ipv4Addr,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Ipv6StatsKey {
    pub source: Ipv6Addr,
    pub dest: Ipv6Addr,
}

// E0117 was in my way so workaround ╮( ╯_╰)╭
#[derive(PartialEq, Eq, Hash)]
pub struct StatsKey(pub Either<Ipv4StatsKey, Ipv6StatsKey>);

impl Serialize for StatsKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where S: Serializer {
        let s = match &self.0 {
            Either::Left(v4) => format!("{} -> {}", v4.source, v4.dest),
            Either::Right(v6) => format!("{} -> {}", v6.source, v6.dest)
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for StatsKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split(" -> ").collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom("Invalid StatsKey format"));
        }
        let (source, dest) = (parts[0], parts[1]);
        if source.contains(':') {
            // Ipv6
            let source = source.parse::<Ipv6Addr>().map_err(serde::de::Error::custom)?;
            let dest = dest.parse::<Ipv6Addr>().map_err(serde::de::Error::custom)?;
            Ok(StatsKey(Either::Right(Ipv6StatsKey { source, dest })))
        } else {
            // Ipv4
            let source = source.parse::<Ipv4Addr>().map_err(serde::de::Error::custom)?;
            let dest = dest.parse::<Ipv4Addr>().map_err(serde::de::Error::custom)?;
            Ok(StatsKey(Either::Left(Ipv4StatsKey { source, dest })))
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct StatsValue {
    pub total_length: u128,
    pub total_count: u128,
}

// Stupid E0117
#[derive(Serialize, Deserialize)]
pub struct Stats(pub HashMap<StatsKey, StatsValue>);

impl Stats {
    pub fn new() -> Self {
        Stats(HashMap::new())
    }
}

impl StatsValue {
    pub fn new() -> Self {
        StatsValue { total_length: 0, total_count: 0 }
    }
}

impl Display for StatsKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Either::Left(v4) => write!(f, "{} -> {}", v4.source, v4.dest),
            Either::Right(v6) => write!(f, "{} -> {}", v6.source, v6.dest)
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

pub fn update_db(mut unlocked_db: MutexGuard<Stats>, stats: (StatsKey, u128)) {
    let unlocked_db = &mut unlocked_db.0;
    let entry = unlocked_db.entry(stats.0).or_insert(StatsValue::new());
    entry.total_count += 1;
    entry.total_length += stats.1;
}
