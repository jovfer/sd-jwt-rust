use crate::utils::{base64_hash, base64url_encode, generate_salt};
#[cfg(feature = "mock_salts")]
use crate::utils::generate_salt_mock;


#[derive(Debug)]
pub(crate) struct SDJWTDisclosure {
    pub raw_b64: String,
    pub hash: String,
}

impl SDJWTDisclosure  {
    pub(crate) fn new<V>(key: Option<String>, value: V) -> Self where V: ToString {
        let mut salt = generate_salt(key.clone());

        #[cfg(feature = "mock_salts")]
        {
            salt = generate_salt_mock(key.clone());
        }

        let mut value_str = value.to_string();
        value_str = value_str.replace(":[", ": [").replace(',', ", ").replace("\":", "\": ").replace("\":  ", "\": ");

        if !value_str.is_ascii() {
            value_str = escape_unicode_chars(&value_str);
        }

        let (_data, raw_b64) = if let Some(key) = &key { //TODO remove data?
            let escaped_key = escape_json(key);
            let data = format!(r#"["{}", "{}", {}]"#, salt, escaped_key, value_str);
            let raw_b64 = base64url_encode(data.as_bytes());
            (data, raw_b64)
        } else {
            let data = format!(r#"["{}", {}]"#, salt, value_str);
            let raw_b64 = base64url_encode(data.as_bytes());
            (data, raw_b64)
        };

        let hash = base64_hash(raw_b64.as_bytes());

        Self {
            raw_b64,
            hash,
        }
    }
}

fn escape_unicode_chars(sss: &str) -> String {
    let mut result = String::new();

    for c in sss.chars() {
        if c.is_ascii() {
            result.push(c);
        } else {
            let esc_c = c.escape_unicode().to_string();

            let esc_c_new = match esc_c.chars().count() {
                6 => esc_c.replace("\\u{", "\\u00").replace("}", ""), // example: \u{de}
                7 => esc_c.replace("\\u{", "\\u0").replace("}", ""),  // example: \u{980}
                8 => esc_c.replace("\\u{", "\\u").replace("}", ""),   // example: \u{23f0}
                _ => {panic!("unsupported")}
            };

            result.push_str(&esc_c_new);
        }
    }

    return result;
}

fn escape_json(s: &str) -> String {
    // TODO: use some library as implementation
    return s.replace("\"", "\\\"");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::base64url_decode;
    use regex::Regex;


    #[test]
    fn test_sdjwt_disclosure_when_key_is_none() {
        let sdjwt_disclosure = SDJWTDisclosure::new(None, "test");
        let decoded_disclosure: String = String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", test]"#).unwrap();
        assert!(re.is_match(&decoded_disclosure));
    }

    #[test]
    fn test_sdjwt_disclosure_when_key_is_present() {
        let sdjwt_disclosure = SDJWTDisclosure::new(Some("key".to_string()), "test");
        let decoded = String::from_utf8(base64url_decode(&sdjwt_disclosure.raw_b64).unwrap()).unwrap();

        let re = Regex::new(r#"\[".*", "key", test]"#).unwrap();
        assert!(re.is_match(&decoded));    }
}
