//! Embedded static management interface.

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "webui"]
pub struct Assets;

pub fn get(path: &str) -> Option<rust_embed::EmbeddedFile> {
    Assets::get(path)
}
