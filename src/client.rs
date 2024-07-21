use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use num::abs;
use rand::thread_rng;
use std::error::Error;
use tonic::transport::Channel;
use zkp_auth::zkp_client::ZkpClient;
use zkp_auth::{ParamsRequest, RegisterRequest, ChallengeRequest, SecretRequest};

mod zkp_auth;

struct ZkpClientWrapper {
    client: ZkpClient<Channel>,
    username: String,
    x: BigInt, // The secret
    p: BigInt,
    q: BigInt,
    g: BigInt,
    h: BigInt,
    y1: BigInt,
    y2: BigInt,
}

impl ZkpClientWrapper {
    async fn new(addr: &str, username: String, secret: BigInt) -> Result<Self, Box<dyn Error>> {
        let channel = Channel::from_shared(addr.to_string())?
            .connect()
            .await?;
        let client = ZkpClient::new(channel);

        let mut wrapper = Self {
            client,
            username,
            x: secret,
            p: BigInt::from(0),
            q: BigInt::from(0),
            g: BigInt::from(0),
            h: BigInt::from(0),
            y1: BigInt::from(0),
            y2: BigInt::from(0),
        };

        wrapper.init_communication().await?;
        wrapper.register().await?;

        Ok(wrapper)
    }

    async fn init_communication(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[INFO] Requesting parameters from server...");
        let request = tonic::Request::new(ParamsRequest {});
        let response = self.client.init_communication(request).await?.into_inner();

        self.p = BigInt::from_bytes_be(Sign::Plus, &response.p);
        self.q = BigInt::from_bytes_be(Sign::Plus, &response.q);
        self.g = BigInt::from_bytes_be(Sign::Plus, &response.g);
        self.h = BigInt::from_bytes_be(Sign::Plus, &response.h);
        
        println!("[DEBUG] - p: {}", self.p.clone());
        println!("[DEBUG] - q: {}", self.q.clone());
        println!("[DEBUG] - g: {}", self.g.clone());
        println!("[DEBUG] - h: {}", self.h.clone());
        Ok(())
    }

    async fn register(&mut self) -> Result<(), Box<dyn Error>> {
        println!("[INFO] Registering user...");
        self.y1 = self.g.modpow(&self.x, &self.p);
        self.y2 = self.h.modpow(&self.x, &self.p);

        println!("[DEBUG] y1: {}", self.y1.clone());
        println!("[DEBUG] y2: {}", self.y2.clone());
        let request = tonic::Request::new(RegisterRequest {
            username: self.username.clone(),
            y1: self.y1.to_bytes_be().1,
            y2: self.y2.to_bytes_be().1,
        });

        self.client.register(request).await?;
        println!("[INFO] User registered successfully");
        Ok(())
    }

    async fn generate_prove(&mut self) -> Result<String, Box<dyn Error>> {
        println!("[INFO] Generating proof...");
        let k = thread_rng().gen_bigint_range(&BigInt::from(0), &self.q);
        println!("[DEBUG] Generated random number k: {}", k);

        // Compute r1 and r2
        let r1 = self.g.modpow(&k, &self.p);
        let r2 = self.h.modpow(&k, &self.p);
        println!("[DEBUG] Computed r1: {}, r2: {}", r1, r2);

        // Send challenge request
        let challenge_request = tonic::Request::new(ChallengeRequest {
            username: self.username.clone(),
            r1: r1.to_bytes_be().1,
            r2: r2.to_bytes_be().1,
        });
        println!("[DEBUG] Sending challenge request...");

        let challenge_response = self.client.challenge(challenge_request).await?.into_inner();
        // Compute the response
        let c = BigInt::from_bytes_be(Sign::Plus, &challenge_response.c);
        let mut s = (&k - c.clone() * &self.x.clone()) % &self.q;
        if s < 0.to_bigint().unwrap() {
            s = s + &self.q;
        }

        println!("[DEBUG] - x: {}", self.x);
        println!("[DEBUG] - k: {}", &k.clone().to_string());
        println!( "[DEBUG] - c: {}",c);
        println!( "[DEBUG] - s: {}",s);

        println!("[INFO] verifying proof...");
        // Send verification request
        let verify_request = tonic::Request::new(SecretRequest {
            username: self.username.clone(),
            s: s.to_bytes_be().1,
        });

        let verify_response = self.client.verify(verify_request).await?.into_inner();
        println!("[DEBUG] Received verification response: {:?}", verify_response);

        Ok(verify_response.session)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[MAIN] Starting client...");
    let addr = "http://[::1]:50051";
    let username = "testuser".to_string();
    let secret = BigInt::from(1234); // This should be a securely generated secret 
    println!("[MAIN] [DEBUG] Initialized parameters username: {} - secret: {}", username, secret);

    let mut client = ZkpClientWrapper::new(addr, username, secret).await?;
    println!("[MAIN] [DEBUG] Initialized client");

    match client.generate_prove().await {
        Ok(session) => {
            if !session.is_empty() {
                println!("Authentication successful! Session: {}", session);
            } else {
                println!("Authentication failed!");
            }
        }
        Err(e) => println!("Error during proof: {}", e),
    }

    Ok(())
}