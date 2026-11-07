//! Removes `//` and `/* */` comments from JSON while preserving byte
//! positions, so a parse error still points at the original line.

use anyhow::{bail, Result};

pub fn strip_json_comments(data: &[u8]) -> Result<Vec<u8>> {
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    let mut out = Vec::with_capacity(data.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut index = 0;

    while index < data.len() {
        let current = data[index];
        if line_comment {
            if current == b'\n' || current == b'\r' {
                line_comment = false;
                out.push(current);
            } else {
                out.push(b' ');
            }
            index += 1;
            continue;
        }
        if block_comment {
            if current == b'*' && index + 1 < data.len() && data[index + 1] == b'/' {
                out.extend_from_slice(b"  ");
                index += 2;
                block_comment = false;
            } else {
                if current == b'\n' || current == b'\r' {
                    out.push(current);
                } else {
                    out.push(b' ');
                }
                index += 1;
            }
            continue;
        }
        if in_string {
            out.push(current);
            if escaped {
                escaped = false;
            } else if current == b'\\' {
                escaped = true;
            } else if current == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if current == b'"' {
            in_string = true;
            out.push(current);
        } else if current == b'/' && index + 1 < data.len() && data[index + 1] == b'/' {
            line_comment = true;
            out.extend_from_slice(b"  ");
            index += 1;
        } else if current == b'/' && index + 1 < data.len() && data[index + 1] == b'*' {
            block_comment = true;
            out.extend_from_slice(b"  ");
            index += 1;
        } else {
            out.push(current);
        }
        index += 1;
    }
    if block_comment {
        bail!("unterminated block comment");
    }
    Ok(out)
}
