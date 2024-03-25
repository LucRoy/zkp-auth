use std::collections::HashMap;
use std::sync::Mutex;

// server.rs
use tonic::{transport::Server, Request, Response, Status, Code};
use zkp_auth::{auth_server::{Auth, AuthServer}, AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};
use uuid::Uuid;
use log::error;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::OsRng;

use crate::models::{AuthChallenge, User, Params};
use crate::constants::PARAMS;

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

#[derive(Default)]
pub struct AuthService {
    users: Mutex<HashMap<String, User>>,
    challenges: Mutex<HashMap<String, AuthChallenge>>,
}

#[tonic::async_trait]
impl Auth for AuthService {

    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {

        let req = request.into_inner();

        let user = User {
            name: req.user.clone(),
            y1: BigUint::from_bytes_be(&req.y1),
            y2: BigUint::from_bytes_be(&req.y2),
        };

        let mut users = self.users.lock().unwrap();
        users.insert(user.name.clone(), user);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("create auth challenge");
        
        let req = request.into_inner();

        let params = &*PARAMS;
        let mut rng = OsRng;
        let c = rng.gen_biguint_below(&params.p);

        let users = self.users.lock().unwrap();
        let user = users.get(&req.user)
                                .ok_or_else(|| Status::new(Code::NotFound, format!("User '{}' not found", &req.user)))?;

        let uid = Uuid::new_v4().to_string();
        let auth_id = AuthChallenge {
            username: user.name.clone(),
            r1: BigUint::from_bytes_be(&req.r1),
            r2: BigUint::from_bytes_be(&req.r2),
            c: c.clone(),
        };

        let mut challenges = self.challenges.lock().unwrap();
        challenges.insert(uid.clone(), auth_id);

        
        return Ok(Response::new(AuthenticationChallengeResponse {
            auth_id: uid,
            c: c.to_bytes_be()
        }))
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("verify auth");
        let req = request.into_inner();

        let challenges = self.challenges.lock().unwrap();
        let c = challenges.get(&req.auth_id)
                                .ok_or_else(|| Status::new(Code::NotFound, format!("Challenge id '{}' not found", &req.auth_id)))?;

        let users = self.users.lock().unwrap();
        let user = users.get(&c.username)
                                .ok_or_else(|| Status::new(Code::NotFound, format!("User '{}' not found", &c.username)))?;

        let s = &BigUint::from_bytes_be(&req.s);

        let (y1, y2, r1, r2) = (&user.y1, &user.y2, &c.r1, &c.r2);

        let params = &*PARAMS;

        let lhs1 = params.g.modpow(s, &params.p);
        let rhs1 = (r1 * y1.modpow(&(&params.p - &c.c - BigUint::one()), &params.p)) % &params.p;
        let lhs2 = params.h.modpow(s, &params.p);
        let rhs2 = (r2 * y2.modpow(&(&params.p - &c.c - BigUint::one()), &params.p)) % &params.p;

        if !(lhs1 == rhs1 && lhs2 == rhs2) {
            error!("Invalid authentication for user: {}", user.name);
            return Err(Status::invalid_argument("Invalid authentication"));
        }
        
        Ok(Response::new(AuthenticationAnswerResponse {
            session_id: Uuid::new_v4().to_string()
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse().unwrap();
    let auth_service = AuthService::default();

    println!("Server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
