use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

// ClaimsはJWTのペイロードに含まれる情報を表す
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn main() {
    let claims = Claims {
        sub: "1234567890".to_string(),
        exp: 1682092565,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("my_secret".as_ref()),
    )
    .unwrap();

    println!("Token is >> {:?}", token);
    let claims = decode::<Claims>(
        &token,
        &DecodingKey::from_secret("my_secret".as_ref()),
        &Validation::default(),
    );

    match claims {
        Ok(c) => println!("Claims are >> {:?}", c.claims),
        Err(e) => println!("Error is >> {:?}", e.kind()),
    }
}
