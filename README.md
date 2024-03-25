### ZKP-AUTH

A quick app to validate a zero knowledge proof using the Chaum-Pedersen Protocol.

## Steps
1. Install dependencies
```
brew install protobuf
```
2. Build Project
```
cargo build --release
```
3. Run Server and Client in seperate terminal
```
./target/release/server
./target/release/client
```