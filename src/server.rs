use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use tokio::sync::Mutex;

use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::zkp_server::{Zkp, ZkpServer};
use zkp_auth::{ParamsResponse, ParamsRequest, RegisterRequest, RegisterResponse, ChallengeRequest, ChallengeResponse, SecretRequest, SecretResponse};
mod zkp_auth;
use num_traits::{ToBytes};

use rand::{thread_rng, Rng};

use num_bigint::{BigInt, RandBigInt, Sign};
use is_prime::*;


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
    let mut rng = thread_rng();
    loop { // Iterates until a safe prime is found
        let q = rng.gen_biguint((bit_length - 1).try_into().unwrap());
        let p = &q * 2u32 + 1u32;
        if is_prime(&q.to_string()) && is_prime(&p.to_string()) {
            return p.into();
        }
    }
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
        // We want to generate P which is a safe prime and q is a subgroup of p. 
        // Safe means that p = 2q + 1, where p and q are both prime numbers
        let p = generate_safe_prime(2048); // 2048 bits = 256 bytes - standard sha256 size 
        let q = (&p - 1) / 2; // Sophie Germain prime

        // Generators should be between 2 and p, and the generator g = 2^((p-1)/q) mod p should be different from 1
        // generators are able to produce any other number in the group p and sub group q
        let g = find_generator(&p, &q);
        let h = find_generator(&p, &q);

        let parameters = Parameters { p: p.clone(), q: q.clone(), g: g.clone(), h: h.clone() };
        *self.parameters.lock().await = Some(parameters); // Save the parameters

        // Prepare the response
        let response = ParamsResponse {
            p: p.to_bytes_be().1,
            q: q.to_bytes_be().1,
            g: g.to_bytes_be().1,
            h: h.to_bytes_be().1,
        };

        println!("response={:?}", response);
        Ok(Response::new(response))
    }

    async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>,Status>{
        println!("request={:?}",request);

        let data = request.get_ref();
        let username = data.username.clone();
        // We could say that y1 and y2 are the public keys of the user
        let y1 = BigInt::from_bytes_be(Sign::Plus, &data.y1);
        let y2 = BigInt::from_bytes_be(Sign::Plus, &data.y2);

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
        println!("Received challenge request: {:?}", request);

        let data = request.get_ref();
        let username = data.username.clone();
        let r1 = BigInt::from_bytes_be(Sign::Plus, &data.r1);
        let r2 = BigInt::from_bytes_be(Sign::Plus, &data.r2);
    
        let params = self.parameters.lock().await;
    
        // random challenge, generate big int in range of q 
        let c: BigInt = thread_rng().gen_bigint_range(&BigInt::from(0), &params.as_ref().unwrap().q);
    
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
    
        println!("Sending challenge response: {:?}", response);
        Ok(Response::new(response))    
    }

    async fn verify(&self, request:Request<SecretRequest>) -> Result<Response<SecretResponse>,Status>{
        println!("request={:?}",request);

        // let data = request.get_ref();
        // let username = data.username.clone();
        // let s: BigInt = BigInt::from_bytes_be(Sign::Plus, &data.s);

        // let c = &self.challenges.lock().await.get(&username).unwrap();

        // let v1 = (self.parameters.g.modpow(s, &self.parameters.p) *  y1.modpow(c, &self.parameters.p)) % &self.parameters.p;
        // let v2 = (self.parameters.h.modpow(s, &self.parameters.p) * 
        //     y2.modpow(c, &self.parameters.p)) % &self.parameters.p;
        //&v1 == r1 && &v2 == r2;

        let response = SecretResponse{ session: "a".to_string() };
        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[INFO] Startint server...");

    let addr = "[::1]:50051".parse().unwrap();
    let zkp = ZkpServerI::default();

    let request = ParamsRequest{};
    zkp.init_communication(Request::new(request)).await?;
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
        
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &params.p), BigInt::from(0));
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &params.q), BigInt::from(0));
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &params.g), BigInt::from(0));
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &params.h), BigInt::from(0));
    }

    #[tokio::test]
    async fn test_register() {
        let server = ZkpServerI::default();
        let y1 = BigInt::from(123).to_bytes_be().1;
        let y2 = BigInt::from(456).to_bytes_be().1;

        let request = Request::new(RegisterRequest {
            username: "test".to_string(),
            y1,
            y2,
        });
        
        let response = server.register(request).await.unwrap();
        assert_eq!(response.get_ref(), &RegisterResponse::default());

        let users = server.users.lock().await;
        assert!(users.contains_key("test"));
        let user = users.get("test").unwrap();
        assert_eq!(user.id, "test");
        assert_eq!(user.y1, BigInt::from(123));
        assert_eq!(user.y2, BigInt::from(456));
    }

    #[tokio::test]
    async fn test_challenge() {
        let server = ZkpServerI::default();
        let r1 = BigInt::from(789).to_bytes_be().1;
        let r2 = BigInt::from(101112).to_bytes_be().1;
        let request = Request::new(ChallengeRequest {
            username: "test".to_string(),
            r1,
            r2,
        });
        
        let response = server.challenge(request).await.unwrap();
        let c = BigInt::from_bytes_be(Sign::Plus, &response.get_ref().c);
        
        assert!(c > BigInt::from(0));

        let challenges = server.challenges.lock().await;
        assert!(challenges.contains_key("test"));
        let challenge = challenges.get("test").unwrap();
        assert_eq!(challenge.id, "test");
        assert_eq!(challenge.r1, BigInt::from(789));
        assert_eq!(challenge.r2, BigInt::from(101112));
        assert_eq!(challenge.c, c);
    }

    #[tokio::test]
    async fn test_verify() {
        let server = ZkpServerI::default();
        let request = Request::new(SecretRequest {
            username: "test".to_string(),
            s: vec![1, 2, 3], // Example s value
        });
        
        let response = server.verify(request).await.unwrap();
        assert_eq!(response.get_ref().session, "a");
    }
}