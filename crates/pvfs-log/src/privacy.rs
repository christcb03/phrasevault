//! What each privacy level lets out of a record (D222 decisions 3a–3d).
//!
//! | class      | full | identified        | minimal                         |
//! |------------|------|-------------------|---------------------------------|
//! | `meta`     | kept | kept              | kept                            |
//! | `actor`    | kept | pseudonym `a:…`   | pseudonym `a:…`                 |
//! | `net`      | kept | kept              | kept on audit/security, else out |
//! | `content`  | kept | `h:…`, `‹name›` in the sentence | the same          |
//! | `identity` | kept | kept              | out, `‹name›` in the sentence   |
//!
//! "Out" also takes the value out of the sentence: a field's value is
//! replaced wherever the sentence holds it (values under 4 characters are
//! not searched for — `a` would hit every word). With no pseudonym key a
//! pseudonym cannot be made, so `actor` and `content` are taken out instead
//! — never sent bare.

use crate::{join_line, Category, Class, Field, Privacy, Record, Value};

/// The record as one output may show it.
#[derive(Clone, Debug, PartialEq)]
pub struct View {
    pub component: Option<String>,
    pub via: Option<String>,
    pub msg: String,
    pub fields: Vec<Field>,
}

impl View {
    pub fn line(&self) -> String {
        join_line(self.via.as_deref(), self.component.as_deref(), &self.msg)
    }
}

/// `a:` or `h:` and the first 12 hex of BLAKE3 keyed with this instance's
/// key: the same value gives the same pseudonym across a fleet sharing the
/// key, and nothing outside it can link two instances.
pub fn pseudonym(key: &[u8; 32], tag: char, value: &str) -> String {
    let h = blake3::keyed_hash(key, value.as_bytes()).to_hex();
    format!("{tag}:{}", &h[..12])
}

enum Fate {
    Keep,
    Out,
    Pseudo(char),
}

pub fn render(rec: &Record, privacy: Privacy, key: Option<&[u8; 32]>) -> View {
    if privacy == Privacy::Full {
        return View {
            component: rec.component.clone(),
            via: rec.via.clone(),
            msg: rec.msg.clone(),
            fields: rec.fields.clone(),
        };
    }
    let security = matches!(rec.category, Category::Audit | Category::Security);
    let mut fields = Vec::with_capacity(rec.fields.len());
    // (what the sentence holds, what it shows instead)
    let mut swaps: Vec<(String, String)> = Vec::new();
    for f in &rec.fields {
        let fate = match (f.class, privacy) {
            (Class::Meta, _) => Fate::Keep,
            (Class::Identity, Privacy::Identified) | (Class::Net, Privacy::Identified) => Fate::Keep,
            (Class::Net, _) if security => Fate::Keep,
            (Class::Net, _) | (Class::Identity, _) => Fate::Out,
            (Class::Actor, _) => Fate::Pseudo('a'),
            (Class::Content, _) => Fate::Pseudo('h'),
        };
        let original = f.value.to_string();
        let stand_in = format!("‹{}›", f.name);
        match fate {
            Fate::Keep => fields.push(f.clone()),
            Fate::Out => swaps.push((original, stand_in)),
            Fate::Pseudo(tag) => match key {
                Some(k) => {
                    let p = pseudonym(k, tag, &original);
                    fields.push(Field { name: f.name.clone(), class: f.class, value: Value::Str(p.clone()) });
                    // An actor's pseudonym is fine in the sentence and lets a
                    // reader follow one actor; content stays a stand-in.
                    swaps.push((original, if tag == 'a' { p } else { stand_in }));
                }
                None => swaps.push((original, stand_in)),
            },
        }
    }
    swaps.retain(|(o, _)| o.chars().count() >= 4);
    // Longest first, so a path is replaced whole before a name inside it.
    swaps.sort_by_key(|s| std::cmp::Reverse(s.0.len()));
    let swap = |s: &str| -> String {
        let mut out = s.to_string();
        for (o, n) in &swaps {
            if out.contains(o.as_str()) {
                out = out.replace(o.as_str(), n);
            }
        }
        out
    };
    View {
        component: rec.component.as_deref().map(swap),
        via: rec.via.as_deref().map(swap),
        msg: swap(&rec.msg),
        fields,
    }
}
