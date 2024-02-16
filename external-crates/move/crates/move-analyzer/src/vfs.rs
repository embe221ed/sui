// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

//! The language server must operate upon Move source buffers as they are being edited.
//! As a result, it is frequently queried about buffers that have not yet (or may never be) saved
//! to the actual file system.
//!
//! To manage these buffers, this module provides a "virtual file system" -- in reality, it is
//! basically just a mapping from file identifier (this could be the file's path were it to be
//! saved) to its textual contents.

use crate::context::Context;
use crate::symbols;
use codespan_reporting::files::SimpleFiles;
use im::HashMap;
use lsp_server::Notification;
use lsp_types::{
    notification::Notification as _, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams,
};
use move_command_line_common::files::FileHash;
use move_compiler::{Flags, parser, SteppedCompiler};
use move_compiler::parser::ast::{Definition, PackageDefinition};
use move_compiler::shared::{CompilationEnv, NamedAddressMaps, NamedAddressMapIndex};
use move_ir_types::location::*;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// A mapping from identifiers (file names, potentially, but not necessarily) to their contents.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VirtualFileSystem {
    pub files: std::collections::HashMap<PathBuf, String>,
}

impl Ord for VirtualFileSystem {
    fn cmp(&self, other: &Self) -> Ordering {
        (0).cmp(&1)
    }
}

impl PartialOrd for VirtualFileSystem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl VirtualFileSystem {
    /// Returns a reference to the buffer corresponding to the given identifier, or `None` if it
    /// is not present in the system.
    pub fn get(&self, identifier: &PathBuf) -> Option<&str> {
        self.files.get(identifier).map(|s| s.as_str())
    }

    /// Inserts or overwrites the buffer corresponding to the given identifier.
    ///
    /// TODO: A far more efficient "virtual file system" would update its buffers with changes sent
    /// from the client, instead of completely replacing them each time. The rust-analyzer has a
    /// 'vfs' module that is capable of doing just that, but it is not published on crates.io. If
    /// we could help get it published, we could use it here.
    pub fn update(&mut self, identifier: PathBuf, content: &str) {
        self.files.insert(identifier, content.to_string());
    }

    /// Removes the buffer and its identifier from the system.
    pub fn remove(&mut self, identifier: &PathBuf) {
        self.files.remove(identifier);
    }
}

/// Updates the given virtual file system based on the text document sync notification that was sent.
/// TODO: the symbolicator_runner won't see the new content of file cause `files.update` won't
/// change it for the object to see. I need to change the logic to pass the `last().text` to the
/// function that parses the sources instead
pub fn on_text_document_sync_notification(
    context: &mut Context,
    symbolicator_runner: &symbols::SymbolicatorRunner,
    notification: &Notification,
) {
    /* fn update_defs(context: &mut Context, fpath: PathBuf, content: &str) {
        use move_compiler::parser::syntax::parse_file_string;
        let file_hash = FileHash::new(content);
        let mut env = CompilationEnv::new(Flags::testing(), Vec::new(), BTreeMap::new(), None);
        let defs = parse_file_string(&mut env, file_hash, content, None);
        let defs = match defs {
            std::result::Result::Ok((x, _)) => x,
            std::result::Result::Err(d) => {
                eprintln!("update file failed,err:{:?}", d);
                return;
            }
        };
        eprintln!("definitions: {:?}", defs);
    } */

    eprintln!("text document notification");
    match notification.method.as_str() {
        lsp_types::notification::DidOpenTextDocument::METHOD => {
            let parameters =
                serde_json::from_value::<DidOpenTextDocumentParams>(notification.params.clone())
                    .expect("could not deserialize notification");
            /* files.update(
                parameters.text_document.uri.to_file_path().unwrap(),
                &parameters.text_document.text,
            ); */
            // update_defs(context, parameters.text_document.uri.to_file_path().unwrap(), &parameters.text_document.text);
            symbolicator_runner.run(parameters.text_document.uri.to_file_path().unwrap());
        }
        lsp_types::notification::DidChangeTextDocument::METHOD => {
            let parameters =
                serde_json::from_value::<DidChangeTextDocumentParams>(notification.params.clone())
                    .expect("could not deserialize notification");
            /* update_defs(
                context,
                parameters.text_document.uri.to_file_path().unwrap(),
                &parameters.content_changes.last().unwrap().text
            ); */
            /* files.update(
                parameters.text_document.uri.to_file_path().unwrap(),
                &parameters.content_changes.last().unwrap().text,
            ); */
            symbolicator_runner.run(parameters.text_document.uri.to_file_path().unwrap());
        }
        lsp_types::notification::DidSaveTextDocument::METHOD => {
            let parameters =
                serde_json::from_value::<DidSaveTextDocumentParams>(notification.params.clone())
                    .expect("could not deserialize notification");
            /* files.update(
                parameters.text_document.uri.to_file_path().unwrap(),
                &parameters.text.unwrap(),
            ); */
            symbolicator_runner.run(parameters.text_document.uri.to_file_path().unwrap());
        }
        lsp_types::notification::DidCloseTextDocument::METHOD => {
            let parameters =
                serde_json::from_value::<DidCloseTextDocumentParams>(notification.params.clone())
                    .expect("could not deserialize notification");
            context.files.remove(&parameters.text_document.uri.to_file_path().unwrap());
        }
        _ => eprintln!("invalid notification '{}'", notification.method),
    }
    eprintln!("text document notification handled");
}
