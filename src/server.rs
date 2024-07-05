use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::zkp_server::{Zkp, ZkpServer};
use zkp_auth::{ZkpResponse, ZkpRequest};
mod zkp_auth; 

#[derive(Default)]
pub struct MyZkp {}

//  rpc.proto service
#[tonic::async_trait]
impl Zkp for MyZkp {
    async fn send(&self,request:Request<ZkpRequest>)->Result<Response<ZkpResponse>,Status>{
        Ok(Response::new(ZkpResponse{
             message:format!("hello {}",request.get_ref().name),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let zkp = MyZkp::default();
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(ZkpServer::new(zkp))
        .serve(addr)
        .await?;
    Ok(())
}