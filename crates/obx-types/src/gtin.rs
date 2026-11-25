//! Validates and normalises GS1 trade item numbers (port of node-go `internal/gtin`).

/// Removes spaces, tabs and no-break spaces (and surrounding white space).
pub fn clean(s: &str) -> String {
    s.trim()
        .chars()
        .filter(|&r| r != ' ' && r != '\t' && r != '\u{a0}')
        .collect()
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Returns the 14-digit form of an 8, 12, 13 or 14 digit code. The check
/// digit is not validated (lenient lookup rule).
pub fn normalize(s: &str) -> Option<String> {
    let s = clean(s);
    if !all_digits(&s) {
        return None;
    }
    match s.len() {
        8 | 12 | 13 | 14 => Some(format!("{}{s}", "0".repeat(14 - s.len()))),
        _ => None,
    }
}

/// Reports whether an 8/12/13/14 digit GTIN (without spaces) has a correct
/// GS1 mod-10 check digit.
pub fn valid_check_digit(s: &str) -> bool {
    let Some(n) = normalize(s) else { return false };
    if clean(s) != s {
        return false;
    }
    let b = n.as_bytes();
    let sum: u32 = (0..13)
        .map(|i| {
            let d = u32::from(b[i] - b'0');
            if i % 2 == 0 { d * 3 } else { d }
        })
        .sum();
    (10 - sum % 10) % 10 == u32::from(b[13] - b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gtin() {
        assert_eq!(
            normalize(" 2000 100101025 ").as_deref(),
            Some("02000100101025")
        );
        assert_eq!(normalize("12345"), None);
        assert!(valid_check_digit("2000100101025"));
        assert!(!valid_check_digit("2000100101026"));
        assert!(valid_check_digit("96385074"));
        assert!(valid_check_digit("012345678905"));
        assert!(!valid_check_digit(" 2000100101025"));
        assert_eq!(
            normalize("2000\u{a0}100101025").as_deref(),
            Some("02000100101025")
        );
    }
}
