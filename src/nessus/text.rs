//! Entity references, resolved by hand: the five predefined entities and
//! numeric character references. A DTD is refused, so no other named entity
//! can be defined; one is an error.

/// What a reference resolved to.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved {
    Char(char),
    /// A numeric reference to something that isn't a Unicode scalar value
    /// (a surrogate, or above U+10FFFF): U+FFFD stands in, with a warning.
    Replaced,
    /// A named entity other than the predefined five.
    Unknown,
}

/// Resolves the text between `&` and `;`.
pub fn resolve(name: &str) -> Resolved {
    match name {
        "amp" => Resolved::Char('&'),
        "lt" => Resolved::Char('<'),
        "gt" => Resolved::Char('>'),
        "quot" => Resolved::Char('"'),
        "apos" => Resolved::Char('\''),
        _ => match name.strip_prefix('#') {
            Some(num) => {
                let n = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => num.parse::<u32>(),
                };
                match n.ok().and_then(char::from_u32) {
                    Some(c) => Resolved::Char(c),
                    None => Resolved::Replaced,
                }
            }
            None => Resolved::Unknown,
        },
    }
}

/// Unescapes an attribute value. Err names the first unknown entity.
/// `replaced` counts numeric references that became U+FFFD.
pub fn unescape(raw: &str, replaced: &mut u64) -> Result<String, String> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let Some(end) = after.find(';') else {
            return Err(format!("an & with no closing ; in {raw:?}"));
        };
        match resolve(&after[..end]) {
            Resolved::Char(c) => out.push(c),
            Resolved::Replaced => {
                *replaced += 1;
                out.push('\u{FFFD}');
            }
            Resolved::Unknown => return Err(format!("unknown entity &{};", &after[..end])),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_predefined_and_numeric_references() {
        assert_eq!(resolve("amp"), Resolved::Char('&'));
        assert_eq!(resolve("#x1b"), Resolved::Char('\u{1b}'));
        assert_eq!(resolve("#233"), Resolved::Char('é'));
        assert_eq!(resolve("#xD800"), Resolved::Replaced);
        assert_eq!(resolve("#x110000"), Resolved::Replaced);
        assert_eq!(resolve("#junk"), Resolved::Replaced);
        assert_eq!(resolve("nbsp"), Resolved::Unknown);
    }

    #[test]
    fn unescapes_attribute_values() {
        let mut n = 0;
        assert_eq!(unescape("A &amp; B &#x41;&#xD800;", &mut n).unwrap(), "A & B A\u{FFFD}");
        assert_eq!(n, 1);
        assert!(unescape("&nbsp;", &mut n).is_err());
        assert!(unescape("a & b", &mut n).is_err());
    }
}
