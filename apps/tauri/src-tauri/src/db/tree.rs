//! Build the initial-tree payload (`GET /api/tree`) straight from the existing
//! Trilium database, mirroring `packages/trilium-core/src/routes/api/tree.ts`.
//!
//! The original loads the whole undeleted note/branch/attribute set into the
//! Becca cache, then for a requested subtree collects the expandable
//! descendants, walks up every collected note's parent branches (ancestors),
//! and folds in the owned attributes (plus `template`/`inherit` relation
//! targets). This module reproduces that shape with a set of plain SQL reads.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;
use serde::Serialize;

/// One note as serialized in the tree payload (`FNoteRow`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteRow {
    pub note_id: String,
    pub title: String,
    pub is_protected: bool,
    #[serde(rename = "type")]
    pub note_type: String,
    pub mime: String,
    pub blob_id: Option<String>,
}

/// One branch as serialized in the tree payload (`FBranchRow`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchRow {
    pub branch_id: String,
    pub note_id: String,
    pub parent_note_id: String,
    pub note_position: i64,
    pub prefix: Option<String>,
    pub is_expanded: bool,
}

/// One attribute as serialized in the tree payload (`FAttributeRow`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttributeRow {
    pub attribute_id: String,
    pub note_id: String,
    pub r#type: String,
    pub name: String,
    pub value: String,
    pub position: i64,
    pub is_inheritable: bool,
}

/// The response body of `GET /tree`.
#[derive(Serialize)]
pub struct SubtreeResponse {
    pub notes: Vec<NoteRow>,
    pub branches: Vec<BranchRow>,
    pub attributes: Vec<AttributeRow>,
}

struct Note {
    note_id: String,
    title: String,
    is_protected: bool,
    note_type: String,
    mime: String,
    blob_id: Option<String>,
}

struct Branch {
    branch_id: String,
    note_id: String,
    parent_note_id: String,
    prefix: Option<String>,
    note_position: i64,
    is_expanded: bool,
}

struct Attribute {
    attribute_id: String,
    note_id: String,
    r#type: String,
    name: String,
    value: String,
    position: i64,
    is_inheritable: bool,
}

#[derive(Default)]
struct Tree {
    notes: HashMap<String, Note>,
    branches: HashMap<String, Branch>,
    attributes: HashMap<String, Attribute>,
    /// child note id -> the branch joining it to a parent; used to walk descendants.
    branches_by_note: HashMap<String, Vec<String>>,
}

/// Load every undeleted note/branch/attribute from the database, mirroring the
/// Becca initial-load queries. Returns `None` when the store has no `notes`
/// table (an uninitialized database).
fn load(conn: &Connection) -> Option<Tree> {
    let mut tree = Tree::default();

    let mut notes = conn
        .prepare("SELECT noteId, title, isProtected, type, mime, blobId FROM notes WHERE isDeleted = 0")
        .ok()?;
    for row in notes
        .query_map([], |r| {
            Ok(Note {
                note_id: r.get(0)?,
                title: r.get(1)?,
                is_protected: r.get::<_, i64>(2)? != 0,
                note_type: r.get(3)?,
                mime: r.get(4)?,
                blob_id: r.get(5)?,
            })
        })
        .ok()?
        .flatten()
    {
        tree.notes.insert(row.note_id.clone(), row);
    }

    let mut branches = conn
        .prepare(
            "SELECT branchId, noteId, parentNoteId, prefix, notePosition, isExpanded FROM branches WHERE isDeleted = 0",
        )
        .ok()?;
    for row in branches
        .query_map([], |r| {
            Ok(Branch {
                branch_id: r.get(0)?,
                note_id: r.get(1)?,
                parent_note_id: r.get(2)?,
                prefix: r.get(3)?,
                note_position: r.get(4)?,
                is_expanded: r.get::<_, i64>(5)? != 0,
            })
        })
        .ok()?
        .flatten()
    {
        tree.branches_by_note
            .entry(row.note_id.clone())
            .or_default()
            .push(row.branch_id.clone());
        tree.branches.insert(row.branch_id.clone(), row);
    }

    let mut attributes = conn
        .prepare(
            "SELECT attributeId, noteId, type, name, value, position, isInheritable FROM attributes WHERE isDeleted = 0",
        )
        .ok()?;
    for row in attributes
        .query_map([], |r| {
            Ok(Attribute {
                attribute_id: r.get(0)?,
                note_id: r.get(1)?,
                r#type: r.get(2)?,
                name: r.get(3)?,
                value: r.get(4)?,
                position: r.get(5)?,
                is_inheritable: r.get::<_, i64>(6)? != 0,
            })
        })
        .ok()?
        .flatten()
    {
        tree.attributes.insert(row.attribute_id.clone(), row);
    }

    Some(tree)
}

/// Render the subtree rooted at `sub_tree_note_id` (default `root`). Returns the
/// JSON the real `/tree` endpoint sends.
pub fn get_tree(conn: &Connection, sub_tree_note_id: &str) -> Option<serde_json::Value> {
    let tree = load(conn)?;
    if !tree.notes.contains_key(sub_tree_note_id) {
        return None;
    }

    // Descendants reachable through expanded branches (mirrors getTree.collect).
    let mut collected: HashSet<String> = HashSet::new();
    collect_descendants(&tree, sub_tree_note_id, &mut collected);

    // Ancestors join through parent branches; plus owned attributes and their
    // template/inherit relation targets (mirrors collectEntityIds).
    let mut note_ids = collected;
    collect_ancestors_and_attributes(&tree, &mut note_ids);

    build_response(&tree, &note_ids)
}

fn collect_descendants(tree: &Tree, note_id: &str, collected: &mut HashSet<String>) {
    if !collected.insert(note_id.to_string()) {
        return;
    }

    if let Some(branch_ids) = tree.branches_by_note.get(note_id) {
        for branch_id in branch_ids {
            if let Some(branch) = tree.branches.get(branch_id) {
                collected.insert(branch.note_id.clone());
                if branch.is_expanded {
                    collect_descendants(tree, &branch.note_id, collected);
                }
            }
        }
    }
}

fn collect_ancestors_and_attributes(tree: &Tree, note_ids: &mut HashSet<String>) {
    let mut processed_branches: HashSet<String> = HashSet::new();
    let mut pending_ids: Vec<String> = note_ids.iter().cloned().collect();

    while let Some(note_id) = pending_ids.pop() {
        // Parent chains: every branch owning this note, plus whose parent.
        for (branch_id, branch) in &tree.branches {
            if branch.note_id == note_id && processed_branches.insert(branch_id.clone()) {
                if note_ids.insert(branch.parent_note_id.clone()) {
                    pending_ids.push(branch.parent_note_id.clone());
                }
            }
        }
        // template / inherit relation targets.
        for attr in tree.attributes.values() {
            if attr.note_id == note_id
                && attr.r#type == "relation"
                && (attr.name == "template" || attr.name == "inherit")
            {
                if !attr.value.is_empty() && note_ids.insert(attr.value.clone()) {
                    pending_ids.push(attr.value.clone());
                }
            }
        }
    }
}

fn build_response(tree: &Tree, note_ids: &HashSet<String>) -> Option<serde_json::Value> {
    // Keep the same field order in every element: id, then parent id, position, …
    let mut notes: Vec<NoteRow> = Vec::new();
    for id in note_ids {
        let note = tree.notes.get(id)?;
        notes.push(NoteRow {
            note_id: note.note_id.clone(),
            title: note.title.clone(),
            is_protected: note.is_protected,
            note_type: note.note_type.clone(),
            mime: note.mime.clone(),
            blob_id: note.blob_id.clone(),
        });
    }

    let mut branches: Vec<BranchRow> = Vec::new();
    if note_ids.contains("root") {
        branches.push(BranchRow {
            branch_id: "none_root".to_string(),
            note_id: "root".to_string(),
            parent_note_id: "none".to_string(),
            note_position: 0,
            prefix: Some(String::new()),
            is_expanded: true,
        });
    }
    for (branch_id, branch) in &tree.branches {
        if note_ids.contains(&branch.note_id) || note_ids.contains(&branch.parent_note_id) {
            branches.push(BranchRow {
                branch_id: branch_id.clone(),
                note_id: branch.note_id.clone(),
                parent_note_id: branch.parent_note_id.clone(),
                note_position: branch.note_position,
                prefix: branch.prefix.clone(),
                is_expanded: branch.is_expanded,
            });
        }
    }
    branches.sort_by_key(|b| (b.parent_note_id.clone(), b.note_position, b.note_id.clone()));

    let mut attributes: Vec<AttributeRow> = Vec::new();
    for (attr_id, attr) in &tree.attributes {
        if note_ids.contains(&attr.note_id) {
            attributes.push(AttributeRow {
                attribute_id: attr_id.clone(),
                note_id: attr.note_id.clone(),
                r#type: attr.r#type.clone(),
                name: attr.name.clone(),
                value: attr.value.clone(),
                position: attr.position,
                is_inheritable: attr.is_inheritable,
            });
        }
    }

    Some(serde_json::to_value(SubtreeResponse {
        notes,
        branches,
        attributes,
    })
    .ok()?)
}