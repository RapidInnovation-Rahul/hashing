use argon2::password_hash::{PasswordHash, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
// use secrecy::{ExposeSecret, Secret};
// use serde::{Deserialize, Serialize};


struct UserInfo{
    username : String,
    password : String,
}
impl UserInfo{
    fn new(u_name : String, u_pass : String)-> Self{
        let u_pass = password_to_phc(u_pass).unwrap();
        Self{
            username : u_name,
            password : u_pass,
        }
    }
    fn verify<'a>(&self , password : &'a str) -> bool {
        let pass = PasswordHash::new(&self.password).unwrap();
        Argon2::default()
            .verify_password(password.as_bytes(), &pass)
            .is_ok()
    }
}
fn main() {
    let u_n = "rahul".to_string();
    let u_p = "rrmondal12@".to_string();
    let c_p = "rrmondal12@".to_string();
    let new_user = UserInfo::new(u_n, u_p);
    println!("username : {} and password : {}", new_user.username, new_user.password);
    let result = new_user.verify(&c_p);
    println!("{}", result);
}


pub fn password_to_phc(password : String) -> Result<String, Box<dyn std::error::Error>>{
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hasher = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).or_else(|_| Err("Error !!!!!!!!".to_string()))?,
    );
    let password_hasher = hasher.hash_password(password.as_bytes(), &salt).unwrap();

    let op = password_hasher.to_string();
    Ok(op)
}
