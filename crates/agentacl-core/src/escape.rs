//! Terminal-safe rendering of attacker-influenced strings (threat model T15b).

/// Escapes C0 controls, DEL and C1 controls so that file names and argv chosen
/// by a supervised agent can never inject terminal escape sequences.
pub fn term_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp < 0x20 || cp == 0x7f {
            out.push_str(&format!("\\x{cp:02x}"));
        } else if (0x80..=0x9f).contains(&cp) || is_invisible_format(cp) {
            out.push_str(&format!("\\u{{{cp:x}}}"));
        } else {
            out.push(c);
        }
    }
    out
}

/// Bidi controls and zero-width characters: they can make a name display as
/// something else (e.g. `evil\u{202e}txt.exe`), so they are shown escaped.
fn is_invisible_format(cp: u32) -> bool {
    matches!(cp, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200B..=0x200F | 0x061C | 0xFEFF)
}

#[cfg(test)]
mod tests {
    use super::term_safe;

    #[test]
    fn escapes_controls_and_keeps_unicode() {
        assert_eq!(term_safe("a\x1b[31mb"), "a\\x1b[31mb");
        assert_eq!(term_safe("naïve"), "naïve");
        assert_eq!(term_safe("x\u{9b}y"), "x\\u{9b}y");
        assert_eq!(term_safe("\n"), "\\x0a");
        assert_eq!(term_safe("\x7f"), "\\x7f");
        assert_eq!(term_safe("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(term_safe("x\u{200b}y"), "x\\u{200b}y");
    }
}
