/// Secret names are metadata. The grammar is in the encryption spec.
pub fn valid_secret_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 || !name.is_ascii() {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '/' | '-'))
    {
        return false;
    }
    name.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_paths_and_rejects_traversal() {
        assert!(valid_secret_name("prod/openai/api_key"));
        assert!(!valid_secret_name("/prod"));
        assert!(!valid_secret_name("prod/../x"));
        assert!(!valid_secret_name("Prod/Key"));
        assert!(!valid_secret_name(""));
    }
}
