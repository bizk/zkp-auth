use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use futures::lock::Mutex;
use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::zkp_server::{Zkp, ZkpServer};
use zkp_auth::{ParamsResponse, ParamsRequest, RegisterRequest, RegisterResponse, ChallengeRequest, ChallengeResponse, SecretRequest, SecretResponse};
mod zkp_auth; 
use num_traits::{ToBytes};
use rand::{thread_rng, Rng};
use num_bigint::{BigInt, RandBigInt, Sign};
//use num_bigint::{BigInt, Sign};


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
}

//  rpc.proto service
#[tonic::async_trait]
impl Zkp for ZkpServerI {
    async fn init_communication(&self,request:Request<ParamsRequest>)->Result<Response<ParamsResponse>,Status>{
        let p = BigInt::from_str("0").unwrap().to_be_bytes();
        let q = BigInt::from_str("0").unwrap().to_be_bytes();
        let g = BigInt::from_str("0").unwrap().to_be_bytes();
        let h = BigInt::from_str("0").unwrap().to_be_bytes();
        
        let response: ParamsResponse = ParamsResponse{
            p,
            q,
            g,
            h,
        };
        println!("response={:?}",response);
        Ok(Response::new(response))
    }

    async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>,Status>{
        println!("request={:?}",request);

        let data = request.get_ref();
        let username = data.username.clone();
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
        println!("request={:?}",request);
 
        // Stores r1, r2
        let data = request.get_ref();

        let username = data.username.clone();
        let r1 = BigInt::from_bytes_be(Sign::Plus, &data.r1);
        let r2 = BigInt::from_bytes_be(Sign::Plus, &data.r2);

        let c: BigInt = thread_rng().gen_bigint(256); // Challenge is a random number
        // let c = BigInt::from_bytes_be(Sign::Plus, &data.c);



        let challenge = Challenge {
            id: username.clone(),
            r1: r1.clone(),
            r2: r2.clone(),
            c: c.clone(),
        };
        
        {
            let mut challenges = self.challenges.lock().await;
            challenges.insert(username.clone(), challenge);
        }

        let response = ChallengeResponse {
            c: c.to_bytes_be().1,
        };
        
        println!("response={:?}",response);
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