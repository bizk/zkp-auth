use zkp_auth::zkp_client::ZkpClient;
use zkp_auth::ZkpRequest;

mod zkp_auth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // channel connection to server
    let channel = tonic::transport::Channel::from_static("http://[::1]:50051")
        .connect()
        .await?;
    let mut client = ZkpClient::new(channel);

    // creating a new Request
    let request = tonic::Request::new(
        ZkpRequest {
           name:String::from("anshul")
        },
    );
    
    // sending request and waiting for response
    let response = client.send(request).await?.into_inner();
    println!("RESPONSE={:?}", response);
    Ok(())
}