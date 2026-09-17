//! D170 — what a view mount remembers of the changes made THROUGH it, until
//! the catalogue agrees.
//!
//! A rename, a `mkdir` or an `rmdir` through the view is done by the box
//! that holds the files (or, for `mkdir`, by nobody yet). That box's watcher
//! catalogues the result and publishes a head; this box fetches it — a
//! minute or two. An arr checks within the second: a verified move stats the
//! target straight after the `rename`. So the mount shows its own changes
//! from memory in between: the rows the catalogue still lists at the old
//! path are shown at the new one.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use pvfs_core::{Engine, ViewCopy, ViewEntry, ViewState};

/// How long a remembered change outlives a catalogue that never agrees —
/// the tombstones' figure (D169).
pub const PENDING_TTL: Duration = Duration::from_secs(600);

/// One rename done through this mount.
#[derive(Clone, Debug)]
pub struct Move {
    pub from: String,
    pub to: String,
    /// The hashes of the file that moved — a NEW file at the old name is
    /// not dragged along. `None` = a folder, and everything under it.
    pub hashes: Option<HashSet<String>>,
    pub at: Instant,
    /// Per region touched: the catalogue seq this box held at the rename.
    pub held: HashMap<String, u64>,
}

/// A folder removed through this mount: when, and the seqs held then.
#[derive(Clone, Debug)]
pub struct GoneDir {
    pub at: Instant,
    pub held: HashMap<String, u64>,
}

#[derive(Default)]
pub struct Overlay {
    /// Oldest first: they compose in that order.
    pub moves: Vec<Move>,
    /// Folders made through this mount that no catalogue lists (mergerfs
    /// clones a path onto our branch before a rename into a new folder).
    pub made_dirs: HashMap<String, Instant>,
    pub gone_dirs: HashMap<String, GoneDir>,
    /// Renames the inode table has not followed yet — a remote rename
    /// finishes on its own thread, and the table is the session thread's.
    pub ino_moves: Vec<(String, String)>,
    /// Listings cached before the last change are stale.
    pub dirty: bool,
}

/// `path` re-rooted from `from` to `to`, when it is `from` or under it.
pub fn rebase(path: &str, from: &str, to: &str) -> Option<String> {
    if path == from {
        return Some(to.to_string());
    }
    path.strip_prefix(from)
        .filter(|rest| rest.starts_with('/'))
        .map(|rest| format!("{to}{rest}"))
}

pub fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map(|(p, _)| p).unwrap_or("")
}

/// Every key that is `from` or under it, re-rooted at `to`.
pub fn rekey<T>(map: &mut HashMap<String, T>, from: &str, to: &str) {
    let moved: Vec<(String, String)> = map.keys().filter_map(|d| rebase(d, from, to).map(|n| (d.clone(), n))).collect();
    for (old, new) in moved {
        if let Some(v) = map.remove(&old) {
            map.insert(new, v);
        }
    }
}

/// `path` is `dir`, or under it.
fn within(path: &str, dir: &str) -> bool {
    path == dir || path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))
}

/// The catalogue seq this box holds per region, now.
pub fn held_seqs(engine: &Engine) -> HashMap<String, u64> {
    engine
        .catalogue_status()
        .map(|s| s.into_iter().filter_map(|r| r.held_seq.map(|q| (r.region, q))).collect())
        .unwrap_or_default()
}

impl Overlay {
    /// Nothing is remembered: the catalogue is the view.
    pub fn is_empty(&self) -> bool {
        self.moves.is_empty() && self.made_dirs.is_empty() && self.gone_dirs.is_empty()
    }

    /// The catalogue paths whose rows may show at view path `rel`: itself,
    /// then `rel` taken back through the pending moves, newest first.
    pub fn origins(&self, rel: &str) -> Vec<String> {
        let mut out = vec![rel.to_string()];
        for m in self.moves.iter().rev() {
            for c in out.clone() {
                let back = match &m.hashes {
                    None => rebase(&c, &m.to, &m.from),
                    Some(_) => (c == m.to).then(|| m.from.clone()),
                };
                if let Some(b) = back.filter(|b| !out.contains(b)) {
                    out.push(b);
                }
            }
        }
        out
    }

    /// Where the catalogue's entry `e` shows in the view: every pending move
    /// applied, oldest first. A file move takes only the copies with the
    /// hashes that moved, so one entry can come out as two.
    pub fn place(&self, e: ViewEntry) -> Vec<ViewEntry> {
        let mut pieces = vec![e];
        for m in &self.moves {
            let mut next = Vec::with_capacity(pieces.len());
            for p in pieces {
                match &m.hashes {
                    None => match rebase(&p.rel_path, &m.from, &m.to) {
                        Some(to) => next.push(ViewEntry { rel_path: to, ..p }),
                        None => next.push(p),
                    },
                    Some(hs) if p.rel_path == m.from && p.kind != "dir" => {
                        let (moved, rest): (Vec<ViewCopy>, Vec<ViewCopy>) = p
                            .sources
                            .iter()
                            .cloned()
                            .partition(|c| c.content_hash.as_ref().is_some_and(|h| hs.contains(h)));
                        if moved.is_empty() {
                            next.push(p);
                        } else if rest.is_empty() {
                            next.push(ViewEntry { rel_path: m.to.clone(), ..p });
                        } else {
                            next.extend(Engine::view_entry_of_copies(&m.to, &moved));
                            next.extend(Engine::view_entry_of_copies(&m.from, &rest));
                        }
                    }
                    Some(_) => next.push(p),
                }
            }
            pieces = next;
        }
        pieces
    }

    /// One entry from the pieces that landed on `rel` — the catalogue's own
    /// row there and rows still listed at an old path can both be present:
    /// one region has published and another has not, or a file was renamed
    /// ONTO another (the replaced file's row is still listed, and a
    /// tombstone hides it). A region's same copy is counted once.
    pub fn merge(rel: &str, mut pieces: Vec<ViewEntry>) -> Option<ViewEntry> {
        if pieces.len() <= 1 {
            return pieces.pop();
        }
        let mut copies: Vec<ViewCopy> = Vec::new();
        for p in pieces {
            for c in p.sources {
                if !copies.iter().any(|o| o.region == c.region && o.content_hash == c.content_hash) {
                    copies.push(c);
                }
            }
        }
        Engine::view_entry_of_copies(rel, &copies)
    }

    /// Where move `i`'s target is NOW: taken on through every later move (a
    /// file renamed inside a folder that was then renamed itself).
    fn final_to(&self, i: usize) -> String {
        let mut at = self.moves[i].to.clone();
        for k in &self.moves[i + 1..] {
            let on = match &k.hashes {
                None => rebase(&at, &k.from, &k.to),
                Some(_) => (at == k.from).then(|| k.to.clone()),
            };
            if let Some(on) = on {
                at = on;
            }
        }
        at
    }

    /// `rel` is a folder this mount vouches for: made here, or on the way
    /// to something renamed here.
    pub fn remembers_dir(&self, rel: &str) -> bool {
        self.made_dirs.contains_key(rel)
            || (0..self.moves.len()).any(|i| {
                let to = self.final_to(i);
                to != rel && within(&to, rel)
            })
    }

    /// The remembered folders directly inside `dir`.
    pub fn remembered_dirs_in(&self, dir: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .made_dirs
            .keys()
            .filter(|d| parent_of(d) == dir && !d.is_empty())
            .cloned()
            .collect();
        for i in 0..self.moves.len() {
            let to = self.final_to(i);
            let rest = if dir.is_empty() {
                Some(to.as_str())
            } else {
                to.strip_prefix(dir).and_then(|r| r.strip_prefix('/'))
            };
            if let Some((first, _)) = rest.and_then(|r| r.split_once('/')) {
                let child = if dir.is_empty() { first.to_string() } else { format!("{dir}/{first}") };
                if !out.contains(&child) {
                    out.push(child);
                }
            }
        }
        out
    }

    /// `rel` is a folder removed through this mount, or under one.
    pub fn is_gone(&self, rel: &str) -> bool {
        self.gone_dirs.keys().any(|g| within(rel, g))
    }

    /// A folder renamed here takes what is remembered under it along: the
    /// folders made there, and the folders removed there — a season folder
    /// removed from `Show`, and `Show` then renamed, must not come back as
    /// `Show Renamed/Season 02` out of the rows the catalogue still lists.
    pub fn rename_made_dirs(&mut self, from: &str, to: &str) {
        rekey(&mut self.made_dirs, from, to);
        rekey(&mut self.gone_dirs, from, to);
    }

    /// Forget what the catalogue has caught up with — or what is too old to
    /// go on vouching for.
    ///
    /// A move is done when every region it touched has published since
    /// **and** nothing of it is listed at `from` any more. Both: with A→B
    /// then B→C the catalogue lists nothing at B from the start, and a head
    /// published from a pass that walked the folder BEFORE the rename still
    /// lists `from`. And a move stays while an older one still feeds it.
    pub fn prune(&mut self, engine: &Engine) {
        if self.is_empty() {
            return;
        }
        let now = held_seqs(engine);
        let republished =
            |held: &HashMap<String, u64>| held.iter().all(|(r, q)| now.get(r).copied().unwrap_or(0) > *q);
        let listed = |rel: &str| engine.view_entry(rel).map(|e| e.is_some()).unwrap_or(true);
        let mut kept: Vec<Move> = Vec::new();
        for m in std::mem::take(&mut self.moves) {
            let fed = kept.iter().any(|k| within(&k.to, &m.from) || within(&m.from, &k.to));
            let left = match &m.hashes {
                None => listed(&m.from) || engine.merged_view(&m.from).map(|l| !l.is_empty()).unwrap_or(true),
                Some(hs) => engine
                    .view_entry(&m.from)
                    .map(|e| {
                        e.is_some_and(|e| {
                            e.sources
                                .iter()
                                .any(|c| c.content_hash.as_ref().is_some_and(|h| hs.contains(h)))
                        })
                    })
                    .unwrap_or(true),
            };
            if (!fed && !left && republished(&m.held)) || m.at.elapsed() > PENDING_TTL {
                self.dirty = true;
            } else {
                kept.push(m);
            }
        }
        self.moves = kept;
        let before = self.made_dirs.len() + self.gone_dirs.len();
        // A made folder the catalogue now lists is simply a folder.
        self.made_dirs.retain(|d, at| at.elapsed() <= PENDING_TTL && !listed(d));
        // A removed folder: gone from the catalogue — or listed by a head
        // published since, which means it is back. "Listed" as the VIEW sees
        // it: a folder removed inside a folder renamed a moment ago is still
        // in the catalogue under its old name (the lab pair: `rmdir` of
        // `Show (2020)/s1` came straight back, listed from `show/s1`).
        let mut gone = std::mem::take(&mut self.gone_dirs);
        gone.retain(|d, g| {
            let shown = self.origins(d).iter().any(|q| match engine.view_entry(q) {
                Ok(Some(e)) => self.place(e).iter().any(|p| &p.rel_path == d),
                Ok(None) => false,
                Err(_) => true,
            });
            g.at.elapsed() <= PENDING_TTL && shown && !republished(&g.held)
        });
        self.gone_dirs = gone;
        if before != self.made_dirs.len() + self.gone_dirs.len() {
            self.dirty = true;
        }
    }
}

/// The entry for a folder only this mount knows.
pub fn remembered_dir(rel: &str) -> ViewEntry {
    ViewEntry {
        rel_path: rel.to_string(),
        kind: "dir".into(),
        size_bytes: 0,
        mtime_ms: 0,
        content_hash: None,
        quality: None,
        state: ViewState::Admitted,
        copies: 0,
        sources: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(rel: &str, copies: &[(&str, &str)]) -> ViewEntry {
        let copies: Vec<ViewCopy> = copies
            .iter()
            .map(|(region, hash)| ViewCopy {
                region: region.to_string(),
                kind: "file".into(),
                size_bytes: 10,
                mtime_ms: 1,
                content_hash: Some(hash.to_string()),
                quality: None,
                stale: false,
            })
            .collect();
        Engine::view_entry_of_copies(rel, &copies).expect("an entry")
    }

    fn mv(from: &str, to: &str, hashes: Option<&[&str]>) -> Move {
        Move {
            from: from.into(),
            to: to.into(),
            hashes: hashes.map(|h| h.iter().map(|s| s.to_string()).collect()),
            at: Instant::now(),
            held: HashMap::new(),
        }
    }

    fn paths(o: &Overlay, e: ViewEntry) -> Vec<String> {
        o.place(e).into_iter().map(|p| p.rel_path).collect()
    }

    #[test]
    fn a_file_move_shows_the_old_row_at_the_new_name() {
        let mut o = Overlay::default();
        o.moves.push(mv("tv/a.mkv", "tv/b.mkv", Some(&["h1"])));
        assert_eq!(paths(&o, file("tv/a.mkv", &[("r1", "h1")])), ["tv/b.mkv"]);
        assert_eq!(o.origins("tv/b.mkv"), ["tv/b.mkv", "tv/a.mkv"]);
        // a NEW file at the old name is not dragged along
        assert_eq!(paths(&o, file("tv/a.mkv", &[("r1", "h2")])), ["tv/a.mkv"]);
        // and an entry holding both comes out as two
        let mut both = paths(&o, file("tv/a.mkv", &[("r1", "h1"), ("r2", "h2")]));
        both.sort();
        assert_eq!(both, ["tv/a.mkv", "tv/b.mkv"]);
    }

    #[test]
    fn moves_compose_and_an_undo_is_nothing() {
        let mut o = Overlay::default();
        o.moves.push(mv("a", "b", Some(&["h"])));
        o.moves.push(mv("b", "c", Some(&["h"])));
        assert_eq!(paths(&o, file("a", &[("r", "h")])), ["c"]);
        assert_eq!(paths(&o, file("b", &[("r", "h")])), ["c"]); // a catalogue between the two
        assert_eq!(o.origins("c"), ["c", "b", "a"]);
        let mut o = Overlay::default();
        o.moves.push(mv("a", "b", Some(&["h"])));
        o.moves.push(mv("b", "a", Some(&["h"])));
        assert_eq!(paths(&o, file("a", &[("r", "h")])), ["a"]);
    }

    #[test]
    fn a_folder_move_takes_its_subtree_and_then_a_file_in_it_can_move() {
        let mut o = Overlay::default();
        o.moves.push(mv("tv/Show", "tv/Show (2020)", None));
        o.moves.push(mv("tv/Show (2020)/s1/e1.mkv", "tv/Show (2020)/s1/E01.mkv", Some(&["h"])));
        assert_eq!(paths(&o, file("tv/Show/s1/e1.mkv", &[("r", "h")])), ["tv/Show (2020)/s1/E01.mkv"]);
        assert_eq!(
            o.origins("tv/Show (2020)/s1/E01.mkv"),
            ["tv/Show (2020)/s1/E01.mkv", "tv/Show (2020)/s1/e1.mkv", "tv/Show/s1/E01.mkv", "tv/Show/s1/e1.mkv"]
        );
        assert_eq!(o.origins("tv/Show (2020)/s1"), ["tv/Show (2020)/s1", "tv/Show/s1"]);
        assert!(o.remembers_dir("tv/Show (2020)"));
        assert!(o.remembers_dir("tv/Show (2020)/s1"));
        assert!(!o.remembers_dir("tv/Show"));
        assert_eq!(o.remembered_dirs_in("tv"), ["tv/Show (2020)"]);
        // "Showtime" is not under "Show"
        assert_eq!(paths(&o, file("tv/Showtime/x.mkv", &[("r", "h")])), ["tv/Showtime/x.mkv"]);
    }

    #[test]
    fn merge_counts_a_regions_copy_once_and_keeps_a_replaced_files_row_apart() {
        let real = file("b", &[("r1", "h")]);
        let ghost = file("b", &[("r1", "h"), ("r2", "h")]);
        let e = Overlay::merge("b", vec![real, ghost]).expect("merged");
        assert_eq!(e.sources.len(), 2);
        assert_eq!(e.copies, 2);
        // renamed ONTO another file of the same region: both rows are there
        // (the mount's tombstone then hides the replaced one)
        let replaced = file("b", &[("r1", "old")]);
        let moved_in = file("b", &[("r1", "h")]);
        let e = Overlay::merge("b", vec![replaced, moved_in]).expect("merged");
        assert_eq!(e.sources.len(), 2);
    }

    #[test]
    fn a_folder_renamed_after_a_move_inside_it_leaves_no_ghost_of_its_old_name() {
        // the lab pair, through mergerfs: a file moved into a new season
        // folder, the old season removed, then the show renamed
        let mut o = Overlay::default();
        o.made_dirs.insert("Show (2020)/s3".into(), Instant::now());
        o.moves.push(mv("Show (2020)/s2/E01.mkv", "Show (2020)/s3/E01.mkv", Some(&["h"])));
        o.gone_dirs.insert("Show (2020)/s2".into(), GoneDir { at: Instant::now(), held: HashMap::new() });
        o.rename_made_dirs("Show (2020)", "Show Renamed (2020)");
        o.moves.push(mv("Show (2020)", "Show Renamed (2020)", None));
        assert_eq!(o.remembered_dirs_in(""), ["Show Renamed (2020)"], "the old name is not vouched for");
        assert!(!o.remembers_dir("Show (2020)") && !o.remembers_dir("Show (2020)/s3"));
        assert!(o.remembers_dir("Show Renamed (2020)/s3"));
        assert!(o.is_gone("Show Renamed (2020)/s2") && !o.is_gone("Show (2020)/s2"));
        assert_eq!(paths(&o, file("Show (2020)/s2/E01.mkv", &[("r", "h")])), ["Show Renamed (2020)/s3/E01.mkv"]);
    }

    #[test]
    fn made_and_gone_folders() {
        let mut o = Overlay::default();
        o.made_dirs.insert("tv/New/Season 01".into(), Instant::now());
        o.made_dirs.insert("tv/New".into(), Instant::now());
        assert_eq!(o.remembered_dirs_in("tv"), ["tv/New"]);
        o.rename_made_dirs("tv/New", "tv/Newer");
        assert!(o.remembers_dir("tv/Newer/Season 01"));
        o.gone_dirs.insert("tv/Old".into(), GoneDir { at: Instant::now(), held: HashMap::new() });
        assert!(o.is_gone("tv/Old/Season 01"));
        assert!(!o.is_gone("tv/Older"));
    }
}
