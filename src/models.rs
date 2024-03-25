use num_bigint::BigUint;

pub struct Params {
    pub p: BigUint,
    pub q: BigUint,
    pub g: BigUint,
    pub h: BigUint,
}

pub struct User {
    pub name: String,
    pub y1: BigUint,
    pub y2: BigUint,
}

pub struct AuthChallenge {
    pub username: String,
    pub r1: BigUint,
    pub r2: BigUint,
    pub c: BigUint,
}

