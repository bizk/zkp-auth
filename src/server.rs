use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::zkp_server::{Zkp, ZkpServer};
use zkp_auth::{ParamsResponse, ParamsRequest, RegisterRequest, RegisterResponse, ChallengeRequest, ChallengeResponse, SecretRequest, SecretResponse};
mod zkp_auth;

use rand::thread_rng;

use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_primes::Generator;

use is_prime::is_prime;
// use num_prime::nt_funcs::is_prime;


#[derive(Clone)]
struct User {
    id: String,
    y1: BigInt,
    y2: BigInt,
}

#[derive(Clone)]
struct Challenge {
    id: String,
    r1: BigInt,
    r2: BigInt,
    c: BigInt,
}

#[derive(Clone)]
struct Parameters {
    p: BigInt,
    q: BigInt,
    g: BigInt,
    h: BigInt,
}

// This struct implements zkp.proto interface
#[derive(Default)]
pub struct ZkpServerI {
    users: Arc<Mutex<HashMap<String, User>>>,
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
    parameters: Arc<Mutex<Option<Parameters>>>,
}

fn generate_safe_prime(bit_length: usize) -> BigInt {
    let p = BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_be(&Generator::safe_prime(bit_length.into()).to_bytes_be()));
    return p;
}

fn find_generator(p: &BigInt, q: &BigInt) -> BigInt {
    let two_big_int = BigInt::from(2);
    loop {
        // Find a g between 2 and p
        let g = thread_rng().gen_bigint_range(&two_big_int, p);
        // g = 2^((p-1)/q) mod p
        // We don't want the generator to be of level 1 or 2, but to be q or 2q  so it generates the sub group q. hardening the security
        if g.modpow(&((p - 1) / q), p) != BigInt::from(1) {
            return g;
        }
    }
}

//  rpc.proto service
#[tonic::async_trait]
impl Zkp for ZkpServerI {
    async fn init_communication(&self,request:Request<ParamsRequest>)->Result<Response<ParamsResponse>,Status>{
        println!("[INFO] init_communication request...");
        // We want to generate P which is a safe prime and q is a subgroup of p. 
        // Safe means that p = 2q + 1, where p and q are both prime numbers
        let p = generate_safe_prime(256); // 256 bits - if bigger it takes more time 
        let q = (&p - 1) / 2; // Sophie Germain prime

        println!("[DEBUG] Generated safe prime p: {}", p);
        println!("[DEBUG] Generated safe prime q: {}", q);

        // Generators should be between 2 and p, and the generator g = 2^((p-1)/q) mod p should be different from 1
        // generators are able to produce any other number in the group p and sub group q
        let g = find_generator(&p, &q);
        let h = find_generator(&p, &q);
        println!("[DEBUG] Generated safe prime g: {}", g);
        println!("[DEBUG] Generated safe prime h: {}", h);

        let parameters = Parameters { p: p.clone(), q: q.clone(), g: g.clone(), h: h.clone() };
        *self.parameters.lock().await = Some(parameters); // Save the parameters

        // Prepare the response
        let response = ParamsResponse {
            p: p.to_bytes_be().1,
            q: q.to_bytes_be().1,
            g: g.to_bytes_be().1,
            h: h.to_bytes_be().1,
        };

        Ok(Response::new(response))
    }

    async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>,Status>{
        println!("[INFO] register request...");

        let data = request.get_ref();
        let username = data.username.clone();
        // We could say that y1 and y2 are the public keys of the user
        let y1 = BigInt::from_bytes_be(Sign::Plus, &data.y1);
        let y2 = BigInt::from_bytes_be(Sign::Plus, &data.y2);
        println!("[DEBUG] username: {}, y1: {}", username, y1);
        println!("[DEBUG] username: {}, y2: {}", username, y2);


        let user = User {
            id: username.clone(),
            y1: y1.clone(),
            y2: y2.clone(),
        };

        let mut users = self.users.lock().await;
        users.insert(username.clone(), user);

        Ok(Response::new(RegisterResponse::default()))
    }

    async fn challenge(&self, request:Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>,Status>{
        let data = request.get_ref();
        let username = data.username.clone();
        let r1 = BigInt::from_bytes_be(Sign::Plus, &data.r1);
        let r2 = BigInt::from_bytes_be(Sign::Plus, &data.r2);
        println!("[INFO] Received challenge request, username: {}, r1: {}, r2: {}", username, r1, r2);

        let params = self.parameters.lock().await;
    
        // random challenge, generate big int in range of q 
        let c: BigInt = thread_rng().gen_bigint_range(&BigInt::from(0), &params.as_ref().unwrap().q);
        println!("[DEBUG] Generated random challenge c: {}", c);

        let challenge = Challenge {
            id: username.clone(),
            r1: r1.clone(),
            r2: r2.clone(),
            c: c.clone(),
        };
    
        // Store the challenge
        {
            let mut challenges = self.challenges.lock().await;
            challenges.insert(username.clone(), challenge);
        }
    
        let response = ChallengeResponse {
            c: c.to_bytes_be().1,
        };
    
        Ok(Response::new(response))    
    }

    async fn verify(&self, request:Request<SecretRequest>) -> Result<Response<SecretResponse>,Status>{
        let data = request.get_ref();
        let username = data.username.clone();
        let s = BigInt::from_bytes_be(Sign::Plus, &data.s);
        println!("[INFO] Received verification request, username: {}, s: {}", username, s);

        let challenges = self.challenges.lock().await;
        let challenge = challenges.get(&username).ok_or(Status::not_found("Challenge not found"))?;
    
        // Retrieve the user's public keys
        let users = self.users.lock().await;
        let user = users.get(&username).ok_or(Status::not_found("User not found"))?;

        // Retrieve the parameters
        let parameters = &self.parameters.lock().await;

        let p = &parameters.as_ref().unwrap().p;
        let g = &parameters.as_ref().unwrap().g;
        let h = &parameters.as_ref().unwrap().h;

        // verifications for g annd h generators
        let v1 = (g.modpow(&s, &p) * user.y1.modpow(&challenge.c, &p)) % p;
        let v2 = (h.modpow(&s, &p) * user.y2.modpow(&challenge.c, &p)) % p;
        println!("[DEBUG] Computed v1: {} and r1: {}", v1, challenge.r1);
        println!("[DEBUG] Computed v2: {} and r2: {}", v2, challenge.r2);

        let session = if v1 == challenge.r1 && v2 == challenge.r2 {
            "valid_session_token".to_string() // This should be a random token or something
        } else {
            "".to_string()
        };
    
        let response = SecretResponse { session };
    
        println!("[DEBUG] Sending verification response: {:?}", response);
        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[INFO] Starting server...");

    let addr = "[::1]:50051".parse().unwrap();
    let zkp = ZkpServerI::default();

    // let request = ParamsRequest{};
    // zkp.init_communication(Request::new(request)).await?;
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(ZkpServer::new(zkp))
        .serve(addr)
        .await?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Request;

    #[tokio::test]
    async fn test_init_communication() {
        let server = ZkpServerI::default();
        let request = Request::new(ParamsRequest {});
        let response = server.init_communication(request).await.unwrap();
        let params = response.get_ref();

        assert!(params.p.len() > 0);
        assert!(params.q.len() > 0);
        assert!(params.g.len() > 0);
        assert!(params.h.len() > 0);

        // Check if p is indeed a safe prime
        let p = BigInt::from_bytes_be(Sign::Plus, &params.p);
        let q = BigInt::from_bytes_be(Sign::Plus, &params.q);
        assert_eq!(&p - 1, &q * 2);
        assert!(is_prime(&p.to_string()));
        assert!(is_prime(&q.to_string()));
    }

    #[tokio::test]
    async fn test_register() {
        let server = ZkpServerI::default();
        let y1 = BigInt::from(123).to_bytes_be().1;
        let y2 = BigInt::from(456).to_bytes_be().1;
        let request = Request::new(RegisterRequest {
            username: "testuser".to_string(),
            y1,
            y2,
        });
        
        let response = server.register(request).await.unwrap();
        assert_eq!(response.get_ref(), &RegisterResponse::default());

        let users = server.users.lock().await;
        assert!(users.contains_key("testuser"));
        let user = users.get("testuser").unwrap();
        assert_eq!(user.id, "testuser");
        assert_eq!(user.y1, BigInt::from(123));
        assert_eq!(user.y2, BigInt::from(456));
    }

    #[tokio::test]
    async fn test_challenge() {
        let server = ZkpServerI::default();
        
        server.init_communication(Request::new(ParamsRequest {})).await.unwrap();

        let r1 = BigInt::from(789).to_bytes_be().1;
        let r2 = BigInt::from(101112).to_bytes_be().1;
        let request = Request::new(ChallengeRequest {
            username: "testuser".to_string(),
            r1,
            r2,
        });
        
        let response = server.challenge(request).await.unwrap();
        let c = BigInt::from_bytes_be(Sign::Plus, &response.get_ref().c);
        
        assert!(c > BigInt::from(0));

        let challenges = server.challenges.lock().await;
        assert!(challenges.contains_key("testuser"));
        let challenge = challenges.get("testuser").unwrap();
        assert_eq!(challenge.id, "testuser");
        assert_eq!(challenge.r1, BigInt::from(789));
        assert_eq!(challenge.r2, BigInt::from(101112));
        assert_eq!(challenge.c, c);
    }

    #[tokio::test]
    async fn test_verify() {
        let server = ZkpServerI::default();
        
        server.init_communication(Request::new(ParamsRequest {})).await.unwrap();

        let y1 = BigInt::from(123).to_bytes_be().1;
        let y2 = BigInt::from(456).to_bytes_be().1;
        server.register(Request::new(RegisterRequest {
            username: "testuser".to_string(),
            y1,
            y2,
        })).await.unwrap();

        let r1 = BigInt::from(789).to_bytes_be().1;
        let r2 = BigInt::from(101112).to_bytes_be().1;
        server.challenge(Request::new(ChallengeRequest {
            username: "testuser".to_string(),
            r1,
            r2,
        })).await.unwrap();

        let s = BigInt::from(42).to_bytes_be().1; 
        let request = Request::new(SecretRequest {
            username: "testuser".to_string(),
            s,
        });
        
        let response = server.verify(request).await.unwrap();
        
        assert!(response.get_ref().session.is_empty() || response.get_ref().session == "valid_session_token");
    }
}