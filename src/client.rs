// client.rs
#[warn(unused_imports)]
use tonic::{transport::Channel, Request};
use zkp_auth::{auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest};
use num_traits::One;
use rand::rngs::OsRng;
use num_bigint::{BigUint, RandBigInt};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

pub struct Params {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub h: BigUint,
}

pub fn commitment(params: &Params, x: &BigUint) -> ((BigUint, BigUint, BigUint, BigUint), BigUint) {
    let y1 = params.g.modpow(x, &params.p);
    let y2 = params.h.modpow(x, &params.p);
    let mut rng = OsRng;
    let k = rng.gen_biguint_below(&params.p);
    let r1 = params.g.modpow(&k, &params.p);
    let r2 = params.h.modpow(&k, &params.p);
    
    ((y1, y2, r1, r2), k)
}

pub fn challenge_response(params: &Params, k: &BigUint, c: &BigUint, x: &BigUint,) -> BigUint {
    if k >= &(c * x) {
        (k - c * x).modpow(&BigUint::one(), &params.q)
    } else {
        &params.q - (c * x - k).modpow(&BigUint::one(), &params.q)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://0.0.0.0:50051")
        .connect()
        .await?;

    let mut client = AuthClient::new(channel);

    let num: u64 = 123456789;
    let x = &BigUint::from(num);
    let params = Params {
        p: BigUint::from(23u32),
        q: BigUint::from(11u32),
        g: BigUint::from(4u32),
        h: BigUint::from(9u32)
    };

    let ((y1, y2, r1, r2), k) = commitment(&params, x);

    let register_request = Request::new(RegisterRequest {
        user: "Luc".into(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    });

    let register_response = client.register(register_request).await?;
    println!("Register Response: {:?}", register_response);

    let auth_challenge_request = Request::new(AuthenticationChallengeRequest {
        user: "Luc".into(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    });

    let auth_challenge_response = client.create_authentication_challenge(auth_challenge_request).await?;
    let inner = auth_challenge_response.into_inner();
    println!("Authentication Challenge Response: {:?}", inner.auth_id);

    let challenge = BigUint::from_bytes_be(&inner.c);
    let cr = challenge_response(&params, &k, &challenge, x);

    // Example: Verify Authentication
    let auth_verify_request = Request::new(AuthenticationAnswerRequest {
        auth_id: inner.auth_id,
        s: cr.to_bytes_be(),
    });
    let auth_verify_response = client.verify_authentication(auth_verify_request).await?;
    println!("Verify Authentication Response: {:?}", auth_verify_response);

    Ok(())
}
