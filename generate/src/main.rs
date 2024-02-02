mod error;
mod types;
mod utils;

use jsonwebtoken::jwk::Jwk;

use crate::error::{Error, ErrorKind, Result};
use clap::Parser;
use jsonwebtoken::{EncodingKey, DecodingKey};
use sd_jwt_rs::issuer::{ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer};
use sd_jwt_rs::holder::SDJWTHolder;
use sd_jwt_rs::verifier::SDJWTVerifier;
use sd_jwt_rs::SDJWTSerializationFormat;
use sd_jwt_rs::utils::{base64_hash, base64url_decode};
#[cfg(feature = "mock_salts")]
use sd_jwt_rs::utils::SALTS;
use serde_json::{Number, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use types::cli::{Cli, GenerateType};
use types::settings::Settings;
use types::specification::Specification;

const ISSUER_KEY_PEM_FILE_NAME: &str = "issuer_key.pem";
const ISSUER_PUBLIC_KEY_PEM_FILE_NAME: &str = "issuer_public_key.pem";
// const HOLDER_KEY_PEM_FILE_NAME: &str = "holder_key.pem";
const SETTINGS_FILE_NAME: &str = "settings.yml";
const SPECIFICATION_FILE_NAME: &str = "specification.yml";
const SALTS_FILE_NAME: &str = "claims_vs_salts.json";
const SD_JWT_FILE_NAME_TEMPLATE: &str = "sd_jwt_issuance";
const VERIFIED_CLAIMS_FILE_NAME: &str = "verified_contents.json";

fn main() {
    let args = Cli::parse();

    println!("type_: {:?}, paths: {:?}", args.type_.clone(), args.paths);

    let basedir = std::env::current_dir().expect("Unable to get current directory");

    // let settings = get_settings(&basedir.join(SETTINGS_FILE_NAME));

    let spec_directories = get_specification_paths(&args, basedir).unwrap();

    for mut directory in spec_directories {
        println!("Generating data for '{:?}'", directory);
        let settings = get_settings(&directory.parent().unwrap().join("..").join(SETTINGS_FILE_NAME));
        let specs = Specification::from(&directory);

        // Remove specification.yaml from path
        directory.pop();

        generate_and_check(&directory, &settings, specs, args.type_.clone()).unwrap();
    }
}

fn generate_and_check(
    directory: &PathBuf,
    settings: &Settings,
    specs: Specification,
    _: GenerateType,
) -> Result<()> {
    let decoy = specs.add_decoy_claims.unwrap_or(false);

    let serialization_format = match specs.serialization_format.clone() {
        Some(format) if format == "json" => SDJWTSerializationFormat::JSON,
        Some(format) if format == "compact" => SDJWTSerializationFormat::Compact,
        None => {
            println!("using default serialization format: Compact");
            SDJWTSerializationFormat::Compact
        },
        Some(format) => {
            panic!("unsupported format: {format}");
        },
    };

    let sd_jwt = issue_sd_jwt(directory, &specs, settings, serialization_format.clone(), decoy)?;
    let presentation = create_presentation(&sd_jwt, serialization_format.clone(), &specs.holder_disclosed_claims);

    // Verify presentation
    let verified_claims = verify_presentation(directory, &presentation, serialization_format.clone());

    let mut json_format = false;
    let mut extension = "txt";

    if specs.serialization_format.is_some() {
        match specs.serialization_format {
            Some(format) if format == "json" => {
                json_format = true;
                extension = "json";
            }
            _ => {}
        }
    }

    let loaded_sd_jwt = load_sd_jwt(&directory.join(format!("{SD_JWT_FILE_NAME_TEMPLATE}.{extension}")))?;

    let loaded_sdjwt_paylod = parse_sdjwt_paylod(&loaded_sd_jwt.replace("\n", ""), json_format, decoy);
    let issued_sdjwt_paylod = parse_sdjwt_paylod(&sd_jwt, json_format, decoy);

    compare_jwt_payloads(&loaded_sdjwt_paylod, &issued_sdjwt_paylod)?;

    let loaded_verified_claims_content = load_sd_jwt(&directory.join(VERIFIED_CLAIMS_FILE_NAME))?;
    let loaded_verified_claims = parse_verified_claims(&loaded_verified_claims_content)?;

    compare_verified_claims(&loaded_verified_claims, &verified_claims)
}

fn issue_sd_jwt(
    directory: &PathBuf,
    specs: &Specification,
    settings: &Settings,
    serialization_format: SDJWTSerializationFormat,
    decoy: bool
) -> Result<String> {
    let issuer_key = get_key(&directory.join(ISSUER_KEY_PEM_FILE_NAME));

    let mut user_claims = specs.user_claims.claims_to_json_value()?;
    let claims_obj = user_claims.as_object_mut().expect("must be an object");

    let iat = settings.iat.expect("'iat' value must be provided by settings.yml");
    let exp = settings.exp.expect("'expt' value must be provided by settings.yml");

    claims_obj.insert(String::from("iss"), Value::String(settings.identifiers.issuer.clone()));
    claims_obj.insert(String::from("iat"), Value::Number(Number::from(iat)));
    claims_obj.insert(String::from("exp"), Value::Number(Number::from(exp)));

    let sd_claims_jsonpaths = specs.user_claims.sd_claims_to_jsonpath()?;

    let strategy =
        ClaimsForSelectiveDisclosureStrategy::Custom(sd_claims_jsonpaths.iter().map(String::as_str).collect());

    let jwk: Option<Jwk> = if specs.key_binding.unwrap_or(false) {
        let jwk: Jwk = serde_yaml::from_value(settings.key_settings.holder_key.clone()).unwrap();
        Some(jwk)
    } else {
        None
    };

    let mut issuer = SDJWTIssuer::new(issuer_key, Some(String::from("ES256")));
    let sd_jwt = issuer.issue_sd_jwt(
            user_claims, 
            strategy,
            jwk,
            decoy,
            serialization_format)
        .unwrap();

    return Ok(sd_jwt);
}

fn create_presentation(
    sd_jwt: &str,
    serialization_format: SDJWTSerializationFormat,
    disclosed_claims: &serde_json::Map<String, serde_json::Value>
) -> String {
    let mut holder = SDJWTHolder::new(sd_jwt.to_string(), serialization_format).unwrap();

    let presentation = holder
        .create_presentation(
            disclosed_claims.clone(),
            None,
            None,
            None,
            None
        ).unwrap();

    return presentation;
}

fn verify_presentation(
    directory: &PathBuf,
    presentation: &str,
    serialization_format: SDJWTSerializationFormat
) -> Value {
    let pub_key_path = directory.clone().join(ISSUER_PUBLIC_KEY_PEM_FILE_NAME);

    let _verified = SDJWTVerifier::new(
        presentation.to_string(),
        Box::new(move |_, _| {
            let key = std::fs::read(&pub_key_path).expect("Failed to read file");
            DecodingKey::from_ec_pem(&key).expect("Unable to create EncodingKey")
        }),
        None,
        None,
        serialization_format,
    ).unwrap();

    return _verified.verified_claims;
}

//

fn remove_decoy_items(m: &serde_json::Value, hashes: &HashSet<String>) -> serde_json::Value {

    let mut mm: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    for (key, val) in m.as_object().unwrap() {
        if key == "_sd" {
            let v1: Vec<_> = val.as_array().unwrap().iter()
                .filter(|item| hashes.contains(item.as_str().unwrap()))
                .map(|item| item.clone())
                .collect();

            let filtered_array = serde_json::Value::Array(v1);
            mm.insert(key.clone(), filtered_array);
        } else if val.is_object() {
            let filtered_object = remove_decoy_items(val, hashes);
            mm.insert(key.clone(), filtered_object);
        } else {
            mm.insert(key.clone(), val.clone());
        }
    }

    return serde_json::Value::Object(mm);
}

fn parse_verified_claims(content: &str) -> Result<Value> {
    let json_value: Value = serde_json::from_str(content)?;

    // TODO: check if the json_value is json object
    return Ok(json_value);
}

fn parse_sdjwt_paylod(sd_jwt: &str, json_format: bool, remove_decoy: bool) -> Value {

    if json_format {
        return parse_payload_json(sd_jwt, remove_decoy);
    }

    return parse_payload_compact(sd_jwt, remove_decoy);
}

fn parse_payload_json(sd_jwt: &str, remove_decoy: bool) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(&sd_jwt).unwrap();

    let disclosures = v.as_object().unwrap().get("disclosures").unwrap();

    let mut hashes: HashSet<String> = HashSet::new();

    for disclosure in disclosures.as_array().unwrap() {
        let hash = base64_hash(disclosure.as_str().unwrap().replace(" ", "").as_bytes());
        hashes.insert(hash.clone());
    }

    let ddd = v.as_object().unwrap().get("payload").unwrap().as_str().unwrap().replace(" ", "");
    let payload = base64url_decode(&ddd).unwrap();

    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();

    if remove_decoy {
        return remove_decoy_items(&payload, &hashes);
    }

    return payload;
}

fn parse_payload_compact(sd_jwt: &str, remove_decoy: bool) -> serde_json::Value {
    let mut disclosures: Vec<String> = sd_jwt
            .split("~")
            .filter(|s| !s.is_empty())
            .map(|s| String::from(s))
            .collect();

    let payload = disclosures.remove(0);

    let payload: Vec<_> = payload.split(".").collect();
    let payload = String::from(payload[1]);

    let mut hashes: HashSet<String> = HashSet::new();

    for disclosure in disclosures {
        let hash = base64_hash(disclosure.as_bytes());
        hashes.insert(hash.clone());
    }

    let payload = base64url_decode(&payload).unwrap();

    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();

    if remove_decoy {
        return remove_decoy_items(&payload, &hashes);
    }

    return payload;
}


fn load_sd_jwt(path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(path)?;
    return Ok(content);
}

fn compare_jwt_payloads(loaded_payload: &Value, issued_payload: &Value) -> Result<()> {
    if issued_payload.eq(loaded_payload) {
        println!("\n\nIssued JWT payload is THE SAME as loaded payload\n\n");
    } else {
        eprintln!("Issued JWT payload is NOT the same as loaded payload");

        println!("Issued SD-JWT \n {:#?}", issued_payload);
        println!("Loaded SD-JWT \n {:#?}", loaded_payload);
    }

    Ok(())
}

fn compare_verified_claims(loaded_claims: &Value, verified_claims: &Value) -> Result<()> {
    if loaded_claims.eq(verified_claims) {
        println!("\n\nVerified claims are THE SAME\n\n",);
    } else {
        eprintln!("Verified claims are NOT the same");

        println!("Issued verified claims \n {:#?}", verified_claims);
        println!("Loaded verified claims \n {:#?}", loaded_claims);
    }

    Ok(())
}

fn get_key(path: &PathBuf) -> EncodingKey {
    let key = std::fs::read(path).expect("Failed to read file");

    EncodingKey::from_ec_pem(&key).expect("Unable to create EncodingKey")
}

fn get_settings(path: &PathBuf) -> Settings {
    println!("settings.yaml - {:?}", path);

    let settings = Settings::from(path);
    println!("{:#?}", settings);

    settings
}

fn get_specification_paths(args: &Cli, basedir: PathBuf) -> Result<Vec<PathBuf>> {
    let glob: Vec<PathBuf>;
    if args.paths.is_empty() {
        glob = basedir
            .read_dir()?
            .filter_map(|entry| {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_dir() && path.join(SPECIFICATION_FILE_NAME).exists() {
                        // load_salts(&path).map_err(|err| Error::from_msg(ErrorKind::IOError, err.to_string()))?;
                        load_salts(&path).unwrap();
                        return Some(path.join(SPECIFICATION_FILE_NAME));
                    }
                }
                None
            })
            .collect();
    } else {
        glob = args
            .paths
            .iter()
            .map(|d| {
                // load_salts(&path).map_err(|err| Error::from_msg(ErrorKind::IOError, err.to_string()))?;
                load_salts(&d).unwrap();
                basedir.join(d).join(SPECIFICATION_FILE_NAME)
            })
            .collect();
    }

    println!("specification.yaml files - {:?}", glob);

    Ok(glob)
}

fn load_salts(path: &PathBuf) -> Result<()> {
    #[cfg(feature = "mock_salts")]
    {
        let salts_path = path.join(SALTS_FILE_NAME);
        let json_data = std::fs::read_to_string(salts_path)
            .map_err(|e| Error::from_msg(ErrorKind::IOError, e.to_string()))?;
        let salts: Vec<String> = serde_json::from_str(&json_data)?;

        {
            let mut s = SALTS.lock().unwrap();

            for salt in salts.iter() {
                s.push_back(salt.clone());
            }
        }
    }

    Ok(())
}
