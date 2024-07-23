# zkp-auth

This project is a Proof of Concept implementation of Chaum Pedersen zero knowledge algorithm. With the purpose to authenticate a user (POWER) against a server (VERIFIER) trough Zero knowledge proofs.

> This is my first time implementing something in rust by scratch. Don't expect some hyper quality code.

The implementation consists of:

- **Proto file**: File `src/zkp.proto` standardizes the communication between client and server. And allows the usage of GRPC.
- **Server**: Also known as the VERIFIER or VALIDATOR implements the code defined in the proto file and listens to any request coming into port: `50051`. It has the following endpoints:
  - init_communication: Provides randomly generated mathematical points required by the zkp-cp algorithm - Prime Scalar Points Q and P. And the generators G and H.
  - User registration: A simple hash map that stores any user that might interact with the server.
  - Challenge: A random generated number used the verifier to generate the proof/
  - Verifier: A function to contrast provided proof by the server information. In other therms to authenticate the user.
- **Client:**: Also known as POWER, connects to the server trough port `50051`, provides its "public key" (points y1 and y2) and goes trough the challenge provided by the server

Both implementations comes with unit tests a docker file each and a docker-compose that allows to run each at the same time.
256
In the demo. The client will connect to the server, exchange the basic information, generate the public key, register itself as "testuser", process the received challenge by the server and submit it. If it goes well, it should receive a token as `valid session token`. Trough the whole process both the server and client will print `[INFO]` stoudt to indicate a new function instantiation and `[DEBUG]` stoudt that shows how the key variables behave.

> Note: The Q and P points have a bit length of 256. Increasing this value might allow to generate "stronger" points but takes more computing power (time, more time...).

## Execute the project

There are 2 ways of running the project, natively or trough docker.

Natively:

1. Start up the server: `cargo run --bin zkp-server`.
2. Start up the client: `cargo run --bin zkp-client`.

By docker:

1. Run `docker-compose up` this will set the server first, then the client and connect them trough a bridged connection.
