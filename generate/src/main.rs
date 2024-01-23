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
#[cfg(feature = "mock_salts")]
use sd_jwt_rs::utils::SALTS;
use serde_json::{Number, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use types::cli::{Cli, GenerateType};
use types::settings::Settings;
use types::specification::Specification;
use serde_json::json;

const ISSUER_KEY_PEM_FILE_NAME: &str = "issuer_key.pem";
const ISSUER_PUBLIC_KEY_PEM_FILE_NAME: &str = "issuer_public_key.pem";
// const HOLDER_KEY_PEM_FILE_NAME: &str = "holder_key.pem";
// const SERIALIZATION_FORMAT: &str = "compact";
const SERIALIZATION_FORMAT: SDJWTSerializationFormat = SDJWTSerializationFormat::JSON;
const SETTINGS_FILE_NAME: &str = "settings.yml";
const SPECIFICATION_FILE_NAME: &str = "specification.yml";
const SALTS_FILE_NAME: &str = "claims_vs_salts.json";
const SD_JWT_PAYLOAD_FILE_NAME: &str = "sd_jwt_payload.json";

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
    // let seed = settings.random_seed.unwrap_or(0);

    // Get keys from .pem files
    let issuer_key = get_key(&directory.join(ISSUER_KEY_PEM_FILE_NAME));
    // let holder_key = get_key(key_path.join(HOLDER_KEY_PEM_FILE_NAME));

    let mut user_claims = specs.user_claims.claims_to_json_value()?;
    let claims_obj = user_claims.as_object_mut().expect("must be an object");

    let iat = settings.iat.expect("'iat' value must be provided by settings.yml");
    let exp = settings.exp.expect("'expt' value must be provided by settings.yml");

    claims_obj.insert(String::from("iss"), Value::String(settings.identifiers.issuer.clone()));
    claims_obj.insert(String::from("iat"), Value::Number(Number::from(iat)));
    claims_obj.insert(String::from("exp"), Value::Number(Number::from(exp)));

    let decoy = specs.add_decoy_claims.unwrap_or(false);
    let sd_claims_jsonpaths = specs.user_claims.sd_claims_to_jsonpath()?;

    let strategy =
        ClaimsForSelectiveDisclosureStrategy::Custom(sd_claims_jsonpaths.iter().map(String::as_str).collect());

    dbg!(&strategy);

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
            SERIALIZATION_FORMAT);

    // let issuer = SDJWTIssuer::issue_sd_jwt(
    //     user_claims,
    //     strategy,
    //     issuer_key,
    //     None,
    //     None,
    //     decoy,
    //     SERIALIZATION_FORMAT.to_string(),
    // );
    // println!("Issued SD-JWT \n {:#?}", sd_jwt.unwrap());

    // return compare_jwt_payloads(
    //     &directory.join(SD_JWT_PAYLOAD_FILE_NAME),
    //     &issuer.sd_jwt_payload,
    // );
    

    // let mut holder = SDJWTHolder::new(
    //     // issuer.serialized_sd_jwt.clone(),
    //     sd_jwt.unwrap().clone(),
    //     SERIALIZATION_FORMAT,
    // ).unwrap();
    // // holder.create_presentation(Some(vec!["address".to_string()]), None, None, None, None);

    // let mut hdc = serde_json::Map::new();
    // let vvvv = json!([true, true, true, true, true, true, true]);
    // hdc.insert(String::from("data_types"), vvvv);
    // dbg!(&hdc);

    // let presentation = holder
    //     .create_presentation(
    //         // specs.holder_disclosed_claims,
    //         hdc,
    //         None,
    //         None,
    //         None,
    //         None
    //         // Some(String::from("1234567890")), // TODO: read it from settings.yml
    //         // aud.clone(),
    //         // holder_key,
    //         // sign_algo,
    //     ).unwrap();
    // dbg!(&presentation);

    // let bbb: serde_json::Value = serde_json::from_str(&presentation).expect("bbb");
    // dbg!(&bbb);
    

    // // Verify presentation
    // // let pub_key_path = directory.clone().join(ISSUER_PUBLIC_KEY_PEM_FILE_NAME);

    // let _verified = SDJWTVerifier::new(
    //     presentation.clone(),
    //     Box::new(|_, _| {
    //         let key = std::fs::read("../../sd-jwt-python/tests/testcases/array_data_types/issuer_public_key.pem").expect("Failed to read file");
    //         DecodingKey::from_ec_pem(&key).expect("Unable to create EncodingKey")
    //     }),
    //     None,
    //     None,
    //     SERIALIZATION_FORMAT,
    // ).unwrap();

    // dbg!(_verified.verified_claims);


    // // println!("Created presentation \n {:?}", holder.sd_jwt_presentation)



    compare_jwt_payloads(
        &directory.join(SD_JWT_PAYLOAD_FILE_NAME),
        &issuer.sd_jwt_payload,
    )
}

fn compare_jwt_payloads(path: &PathBuf, compare: &serde_json::Map<String, Value>) -> Result<()> {
    let contents = std::fs::read_to_string(path)?;

    let json_value: serde_json::Map<String, Value> = serde_json::from_str(&contents)
        .expect(&format!("Failed to parse to serde_json::Value {:?}", path));

    if json_value.eq(compare) {
        println!("\n\nIssued JWT payload is THE SAME as payload of {:?}\n\n", path);
    } else {
        eprintln!(
            "Issued JWT payload is NOT the same as payload of {:?}",
            path
        );

        println!("Issued SD-JWT \n {:#?}", compare);
        println!("Loaded SD-JWT \n {:#?}", json_value);
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


        dbg!(&salts);

        {
            let mut map = SALTS.lock().unwrap();

            for salt in salts.iter() {
                map.push_back(salt.clone());
            }

            dbg!(&map);
        }
    }

    Ok(())
}
