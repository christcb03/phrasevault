//! Tree walk types — spec §12.

use crate::node::Node;

/// One yielded entry of a pre-order walk: `(node, depth, link_type)`.
/// `ref` children are yielded but never descended; the `contains` hierarchy
/// is a strict tree (one-home rule), so each node appears exactly once.
#[derive(Debug, Clone)]
pub struct WalkEntry {
    pub node: Node,
    pub depth: usize,
    pub link_type: String,
}

/// An eagerly materialized pre-order traversal (P0: trees are local and the
/// projection is indexed by `(parent_id, order_key)`, so this is one indexed
/// scan per folder).
#[derive(Debug, Default)]
pub struct TreeWalk {
    pub entries: Vec<WalkEntry>,
}

impl IntoIterator for TreeWalk {
    type Item = WalkEntry;
    type IntoIter = std::vec::IntoIter<WalkEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl TreeWalk {
    pub fn iter(&self) -> std::slice::Iter<'_, WalkEntry> {
        self.entries.iter()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
