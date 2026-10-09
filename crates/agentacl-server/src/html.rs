//! Server-rendered pages: escaping (every value from a Mac is untrusted),
//! the page frame, times, and form decoding.

use std::collections::HashMap;

/// Escapes text for HTML element content and quoted attribute values.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => o.push('\u{fffd}'),
            c => o.push(c),
        }
    }
    o
}

/// Percent-encodes a query value.
pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                Ok(v) => {
                    out.push(v);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `a=1&b=2` (a form body or a query string).
pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').unwrap_or((p, ""))).map(|(k, v)| (decode(k), decode(v))).collect()
}

/// `2026-10-09 15:04 UTC` for unix seconds.
pub fn time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

/// "3 min ago" style, for last-seen columns.
pub fn ago(secs: i64, now: i64) -> String {
    let d = (now - secs).max(0);
    match d {
        0..=59 => format!("{d} s ago"),
        60..=3599 => format!("{} min ago", d / 60),
        3600..=172_799 => format!("{} h ago", d / 3600),
        _ => format!("{} days ago", d / 86_400),
    }
}

/// The page frame. `body` must already be escaped HTML.
pub fn page(title: &str, active: &str, csrf: Option<&str>, body: &str) -> String {
    let nav = [("Machines", "/"), ("Events", "/events"), ("Company policy", "/policy"), ("Enrollment", "/tokens")]
        .iter()
        .map(|(n, href)| format!("<a href=\"{href}\"{}>{n}</a>", if *n == active { " class=\"on\"" } else { "" }))
        .collect::<Vec<_>>()
        .join("");
    let logout = csrf
        .map(|c| format!("<form method=\"post\" action=\"/logout\" class=\"logout\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button>Sign out</button></form>", esc(c)))
        .unwrap_or_default();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{} · AgentACL fleet</title><link rel=\"stylesheet\" href=\"/static/app.css\"></head><body><header><span class=\"brand\">AgentACL fleet</span><nav>{}</nav>{}</header><main>{}</main></body></html>",
        esc(title),
        if csrf.is_some() { nav } else { String::new() },
        logout,
        body
    )
}

/// A hidden CSRF field for forms.
pub fn csrf_field(csrf: &str) -> String {
    format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", esc(csrf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_everything_from_a_mac() {
        assert_eq!(esc("<script>alert('x')</script>&\""), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;");
        assert_eq!(esc("a\u{1b}[31mb"), "a\u{fffd}[31mb");
    }

    #[test]
    fn forms_and_times() {
        let f = parse_form("name=My+Macs&days=30&yaml=version%3A%20v1%0A&bad=%zz&x");
        assert_eq!(f["name"], "My Macs");
        assert_eq!(f["yaml"], "version: v1\n");
        assert_eq!(f["bad"], "%zz");
        assert_eq!(f["x"], "");
        assert_eq!(enc("a b/é"), "a%20b%2F%C3%A9");
        assert_eq!(time(0), "1970-01-01 00:00 UTC");
        assert_eq!(time(1_791_561_600), "2026-10-09 16:00 UTC");
        assert_eq!(ago(100, 160), "1 min ago");
    }
}
