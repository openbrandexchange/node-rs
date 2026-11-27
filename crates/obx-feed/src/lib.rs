//! The change feed of the Open Brand Exchange protocol (protocol.md §6),
//! independent of storage.
//!
//! A first call without a cursor starts a **snapshot**: every visible
//! brand, product, variant and asset, in that order and by id, as `upsert`
//! entries. The snapshot remembers the feed's high-water mark; after the
//! last object the cursor switches to **live** entries after that mark, so
//! nothing written during the snapshot is lost. This crate owns those rules
//! and the cursor (which is node-go's wire format); a [`FeedSource`] reads
//! the objects and entries from wherever they are stored and renders them
//! for the viewer.
//!
//! Cursor errors follow the spec: a cursor that is malformed or signed by
//! another node is `cursor_invalid` (400); a snapshot older than 24 hours, a
//! cursor older than the retained history, or one from before an
//! incompatible upgrade (a new *epoch*) is `cursor_expired` (410).
//!
//! ```
//! use obx_feed::{Feed, FeedSource, LiveBatch, SnapshotBatch};
//! use serde_json::{json, Value};
//!
//! struct Mem(Vec<(String, Value)>); // products only, no live entries
//! impl FeedSource for Mem {
//!     type Error = std::convert::Infallible;
//!     fn high_water(&mut self) -> Result<i64, Self::Error> { Ok(0) }
//!     fn snapshot(&mut self, kind: &str, after: &str, limit: usize) -> Result<SnapshotBatch, Self::Error> {
//!         let items: Vec<_> = if kind == "product" {
//!             self.0.iter().filter(|(id, _)| id.as_str() > after).cloned().collect()
//!         } else { vec![] };
//!         let more = items.len() > limit;
//!         Ok(SnapshotBatch { entries: items.into_iter().take(limit).map(|(i, v)| (i, Some(v))).collect(), more })
//!     }
//!     fn live(&mut self, after: i64, _limit: usize) -> Result<LiveBatch, Self::Error> {
//!         Ok(LiveBatch { changes: vec![], last_seq: after, more: false })
//!     }
//! }
//!
//! let codec = obx_auth::CursorCodec::new(obx_auth::Keys::new(b"secret secret secret secret secret"), "nod_1");
//! let feed = Feed::new(&codec, 0, 0);
//! let mut src = Mem(vec![("prd_1".into(), json!({"seq": 1})), ("prd_2".into(), json!({"seq": 2}))]);
//! let p1 = feed.page(&mut src, "", 1).unwrap();
//! assert_eq!((p1.changes.len(), p1.phase, p1.has_more), (1, "snapshot", true));
//! let p2 = feed.page(&mut src, &p1.next_cursor, 10).unwrap();
//! assert_eq!(p2.changes.len(), 1);
//! let p3 = feed.page(&mut src, &p2.next_cursor, 10).unwrap();
//! assert_eq!((p3.phase, p3.has_more), ("live", false));
//! ```
#![forbid(unsafe_code)]

use obx_auth::CursorCodec;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The object types of a snapshot, in order.
pub const SNAPSHOT_TYPES: [&str; 4] = ["brand", "product", "variant", "asset"];
/// A snapshot cursor older than this is expired.
pub const SNAPSHOT_MAX_AGE_SECS: i64 = 24 * 3600;
/// The cursor kind used to sign feed cursors.
pub const CURSOR_KIND: &str = "changes";

fn is_zero(v: &i64) -> bool {
    *v == 0
}
fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

/// The feed cursor (node-go's field names, kept short on the wire).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// Phase: `s` (snapshot) or `l` (live).
    pub p: String,
    /// Snapshot: the high-water mark taken at its start.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub h: i64,
    /// Snapshot: index into [`SNAPSHOT_TYPES`].
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub t: usize,
    /// Snapshot: the last id returned of the current type.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub a: String,
    /// Snapshot: when it started (Unix seconds).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub c: i64,
    /// Live: the last sequence number returned.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub s: i64,
    /// The epoch the cursor belongs to.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub e: i64,
}

/// One snapshot read: entries by ascending id. `None` data means the object
/// was passed over (for instance an asset whose rights expired): the cursor
/// moves past it without an entry.
#[derive(Debug, Default)]
pub struct SnapshotBatch {
    pub entries: Vec<(String, Option<Value>)>,
    /// More objects of this type follow.
    pub more: bool,
}

/// One live read.
#[derive(Debug, Default)]
pub struct LiveBatch {
    /// The entries for the viewer, at most the requested number.
    pub changes: Vec<Value>,
    /// The last sequence number looked at (also when it was not for this
    /// viewer), where the next page starts.
    pub last_seq: i64,
    /// Entries after `last_seq` exist.
    pub more: bool,
}

/// Where a node keeps its objects and change entries.
pub trait FeedSource {
    type Error;
    /// The highest sequence number written.
    fn high_water(&mut self) -> Result<i64, Self::Error>;
    /// Up to `limit` visible objects of `kind` with an id greater than
    /// `after` (ascending), rendered as change entries for the viewer.
    fn snapshot(
        &mut self,
        kind: &str,
        after: &str,
        limit: usize,
    ) -> Result<SnapshotBatch, Self::Error>;
    /// Up to `limit` entries for the viewer with a sequence number greater
    /// than `after`.
    fn live(&mut self, after: i64, limit: usize) -> Result<LiveBatch, Self::Error>;
}

/// A ChangesPage.
#[derive(Debug, Clone, Serialize)]
pub struct Page {
    pub changes: Vec<Value>,
    pub next_cursor: String,
    pub has_more: bool,
    pub phase: &'static str,
}

impl Page {
    /// Narrows every entry's `data` to a language selection (protocol.md
    /// §2.3). The cursor, the entries and their order do not depend on the
    /// selection, so a consumer may change `lang` between pages.
    pub fn narrow(&mut self, sel: &obx_types::lang::Selection, languages: &[String]) {
        for e in &mut self.changes {
            obx_types::lang::narrow_change(e, sel, languages);
        }
    }
}

/// Why a cursor was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorError {
    /// `cursor_invalid` (400).
    Invalid,
    /// `cursor_expired` (410): restart without a cursor.
    Expired(ExpiredReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiredReason {
    /// The node moved to a new epoch (an incompatible upgrade).
    Epoch,
    /// The snapshot started more than 24 hours ago.
    SnapshotTooOld,
    /// The live position is older than the retained history.
    Pruned,
}

impl CursorError {
    /// The OBX error code.
    pub fn code(&self) -> &'static str {
        match self {
            CursorError::Invalid => "cursor_invalid",
            CursorError::Expired(_) => "cursor_expired",
        }
    }

    /// The text node-go answers with.
    pub fn detail(&self, spec_version: &str) -> String {
        match self {
            CursorError::Invalid => {
                "The cursor is malformed or from another node; restart without a cursor.".into()
            }
            CursorError::Expired(ExpiredReason::Epoch) => format!(
                "This cursor was issued before the node upgraded to incompatible object shapes (now spec {spec_version}); restart without a cursor."
            ),
            CursorError::Expired(ExpiredReason::SnapshotTooOld) => {
                "This snapshot is older than 24 hours; restart without a cursor.".into()
            }
            CursorError::Expired(ExpiredReason::Pruned) => {
                "This cursor is older than the retained history; restart without a cursor.".into()
            }
        }
    }
}

#[derive(Debug)]
pub enum FeedError<E> {
    Cursor(CursorError),
    Source(E),
}

impl<E> From<E> for FeedError<E> {
    fn from(e: E) -> Self {
        FeedError::Source(e)
    }
}

/// The feed state of one node.
pub struct Feed<'a> {
    codec: &'a CursorCodec,
    epoch: i64,
    pruned_below: i64,
    now: i64,
}

impl<'a> Feed<'a> {
    /// `epoch`: the current cursor epoch; `pruned_below`: the lowest
    /// sequence number still retained (0 = nothing pruned).
    pub fn new(codec: &'a CursorCodec, epoch: i64, pruned_below: i64) -> Feed<'a> {
        Feed {
            codec,
            epoch,
            pruned_below,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }

    /// The clock (Unix seconds), for tests.
    pub fn at(mut self, now: i64) -> Self {
        self.now = now;
        self
    }

    /// Decodes and checks a cursor ("" = start a snapshot; `high_water` is
    /// only called then).
    pub fn position<S: FeedSource>(
        &self,
        src: &mut S,
        cursor: &str,
    ) -> Result<Cursor, FeedError<S::Error>> {
        if cursor.is_empty() {
            return Ok(Cursor {
                p: "s".into(),
                h: src.high_water()?,
                c: self.now,
                e: self.epoch,
                ..Default::default()
            });
        }
        let cur: Cursor = self
            .codec
            .decode(CURSOR_KIND, cursor)
            .filter(|c: &Cursor| c.p == "s" || c.p == "l")
            .ok_or(FeedError::Cursor(CursorError::Invalid))?;
        if cur.e != self.epoch {
            return Err(FeedError::Cursor(CursorError::Expired(
                ExpiredReason::Epoch,
            )));
        }
        if cur.p == "s" && self.now - cur.c > SNAPSHOT_MAX_AGE_SECS {
            return Err(FeedError::Cursor(CursorError::Expired(
                ExpiredReason::SnapshotTooOld,
            )));
        }
        if cur.p == "l" && self.pruned_below > 0 && cur.s < self.pruned_below {
            return Err(FeedError::Cursor(CursorError::Expired(
                ExpiredReason::Pruned,
            )));
        }
        Ok(cur)
    }

    /// One page of at most `limit` entries.
    pub fn page<S: FeedSource>(
        &self,
        src: &mut S,
        cursor: &str,
        limit: usize,
    ) -> Result<Page, FeedError<S::Error>> {
        let limit = limit.max(1);
        let mut cur = self.position(src, cursor)?;
        if cur.p == "l" {
            let b = src.live(cur.s, limit)?;
            let next = Cursor {
                p: "l".into(),
                s: b.last_seq,
                e: self.epoch,
                ..Default::default()
            };
            return Ok(Page {
                changes: b.changes,
                next_cursor: self.codec.encode(CURSOR_KIND, &next),
                has_more: b.more,
                phase: "live",
            });
        }
        let mut changes = Vec::new();
        while cur.t < SNAPSHOT_TYPES.len() {
            let room = limit - changes.len();
            let b = src.snapshot(SNAPSHOT_TYPES[cur.t], &cur.a, room)?;
            for (id, data) in b.entries.into_iter().take(room) {
                cur.a = id;
                if let Some(d) = data {
                    changes.push(d);
                }
            }
            if b.more || changes.len() >= limit {
                return Ok(Page {
                    changes,
                    next_cursor: self.codec.encode(CURSOR_KIND, &cur),
                    has_more: true,
                    phase: "snapshot",
                });
            }
            cur.t += 1;
            cur.a.clear();
        }
        let next = Cursor {
            p: "l".into(),
            s: cur.h,
            e: cur.e,
            ..Default::default()
        };
        Ok(Page {
            changes,
            next_cursor: self.codec.encode(CURSOR_KIND, &next),
            has_more: true,
            phase: "snapshot",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obx_auth::Keys;

    struct Src {
        hw: i64,
        live_calls: Vec<i64>,
    }
    impl FeedSource for Src {
        type Error = ();
        fn high_water(&mut self) -> Result<i64, ()> {
            Ok(self.hw)
        }
        fn snapshot(&mut self, kind: &str, after: &str, limit: usize) -> Result<SnapshotBatch, ()> {
            let ids: Vec<String> = (1..=3)
                .map(|i| format!("{kind}_{i}"))
                .filter(|i| i.as_str() > after)
                .collect();
            let more = ids.len() > limit;
            Ok(SnapshotBatch {
                entries: ids
                    .into_iter()
                    .take(limit)
                    .map(|i| {
                        let skip = i == "asset_2";
                        let v = serde_json::json!({"id": i});
                        (i, (!skip).then_some(v))
                    })
                    .collect(),
                more,
            })
        }
        fn live(&mut self, after: i64, _limit: usize) -> Result<LiveBatch, ()> {
            self.live_calls.push(after);
            Ok(LiveBatch {
                changes: vec![],
                last_seq: after,
                more: false,
            })
        }
    }

    fn codec() -> CursorCodec {
        CursorCodec::new(Keys::new(b"0123456789abcdef0123456789abcdef"), "nod")
    }

    #[test]
    fn snapshot_then_live_from_the_high_water_mark() {
        let c = codec();
        let f = Feed::new(&c, 3, 0).at(1000);
        let mut s = Src {
            hw: 42,
            live_calls: vec![],
        };
        let mut cursor = String::new();
        let mut n = 0;
        loop {
            let p = f.page(&mut s, &cursor, 5).unwrap();
            cursor = p.next_cursor;
            if p.phase == "live" {
                break;
            }
            n += p.changes.len();
        }
        assert_eq!(n, 11, "4 types × 3 objects, one asset passed over");
        assert_eq!(s.live_calls, vec![42]);
    }

    #[test]
    fn narrowing_a_page_keeps_cursor_and_entries() {
        let c = codec();
        let mut s = Src {
            hw: 7,
            live_calls: vec![],
        };
        let f = Feed::new(&c, 0, 0).at(1000);
        let mut p = f.page(&mut s, "", 2).unwrap();
        let (cursor, n) = (p.next_cursor.clone(), p.changes.len());
        p.changes.push(
            serde_json::json!({"seq": 8, "type": "product", "op": "upsert",
            "data": {"name": {"en": "Sweater", "nl": "Trui"}}}),
        );
        let sel = obx_types::lang::Selection {
            tag: "nl".into(),
            universal: false,
        };
        p.narrow(&sel, &["nl".to_string(), "en".to_string()]);
        assert_eq!((p.next_cursor, p.changes.len()), (cursor, n + 1));
        assert_eq!(
            p.changes[n]["data"]["name"],
            serde_json::json!({"nl": "Trui"})
        );
        assert_eq!(
            p.changes[n]["data"]["language_fallbacks"],
            serde_json::json!({})
        );
    }

    #[test]
    fn cursor_errors() {
        let c = codec();
        let mut s = Src {
            hw: 1,
            live_calls: vec![],
        };
        let p = Feed::new(&c, 1, 0).at(1000).page(&mut s, "", 2).unwrap();
        let err = |f: Feed, cur: &str, s: &mut Src| match f.page(s, cur, 2) {
            Err(FeedError::Cursor(e)) => Some(e),
            _ => None,
        };
        assert_eq!(
            err(Feed::new(&c, 2, 0).at(1000), &p.next_cursor, &mut s),
            Some(CursorError::Expired(ExpiredReason::Epoch))
        );
        assert_eq!(
            err(Feed::new(&c, 1, 0).at(1000 + 86401), &p.next_cursor, &mut s),
            Some(CursorError::Expired(ExpiredReason::SnapshotTooOld))
        );
        assert_eq!(
            err(Feed::new(&c, 1, 0).at(1000), "garbage", &mut s),
            Some(CursorError::Invalid)
        );
        let live = c.encode(
            CURSOR_KIND,
            &Cursor {
                p: "l".into(),
                s: 5,
                e: 1,
                ..Default::default()
            },
        );
        assert_eq!(
            err(Feed::new(&c, 1, 10).at(1000), &live, &mut s),
            Some(CursorError::Expired(ExpiredReason::Pruned))
        );
        assert!(err(Feed::new(&c, 1, 5).at(1000), &live, &mut s).is_none());
    }
}
