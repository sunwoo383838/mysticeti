use crate::types::ark_se_de_as_bytes;
use std::ops::Mul;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, EdwardsAffine as JubJubAffine, Fr};

use ark_crypto_primitives::encryption::elgamal;
use ark_crypto_primitives::encryption::elgamal::Ciphertext;
use ark_ff::{PrimeField, Field, Zero, One, UniformRand};
use ark_std::rand;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub index: u64,
    #[serde(with = "ark_se_de_as_bytes")]
    pub value: Fr,
}

pub fn encode_vote(vote: u64, g: &JubJubAffine) -> JubJubAffine {
    if vote == 0 {
        JubJub::zero().into_affine()
    } else {
        g.mul(Fr::from(vote)).into_affine()
    }
}

pub fn elgamal_encrypt(
    msg_point: &JubJubAffine,
    pk: &JubJubAffine,
    g: &JubJubAffine,
    r: Fr,
) -> (JubJubAffine, JubJubAffine) {
    // C1 = r * G
    let c1 = g.mul(r).into_affine();

    // C2 = M + r * PK
    let r_pk = pk.mul(r);
    let c2 = (msg_point.into_group() + r_pk).into_affine();

    (c1, c2)
}

/// f(x) = a0 + a1 x + ... + a_{t-1} x^{t-1}
pub fn eval_poly(coeffs: &[Fr], x: Fr) -> Fr {
    // Horner가 제일 빠르지만, 지수 작은 편이므로 단순 전개도 충분
    let mut acc = Fr::zero();
    let mut pow_x = Fr::one();
    for a in coeffs {
        acc += *a * pow_x;
        pow_x *= x;
    }
    acc
}

pub fn feldman_commitments(coeffs: &[Fr], g: JubJubAffine) -> Vec<JubJubAffine> {
    coeffs
        .iter()
        .map(|a_j| g.mul(a_j).into_affine())
        .collect()
}

pub fn shamir_split_with_commitments<R: rand::Rng>(
    secret: Fr,
    t: usize,
    n: usize,
    g: JubJubAffine,
    rng: &mut R,
) -> (Vec<Share>, Vec<Fr>, Vec<JubJubAffine>) {
    // ...
    // 계수 생성: a0 = secret, a1..a_{t-1} 랜덤
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(secret); // a_0 = secret
    for _ in 1..t {
        coeffs.push(Fr::rand(rng)); // a_1 ... a_{t-1}
    }

    // shares: i = 1..=n
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n as u64 {
        let xi = Fr::from(i);
        let yi = eval_poly(&coeffs, xi); // y_i = f(x_i)
        shares.push(Share { index: i, value: yi });
    }

    // Feldman commitments: V_j = a_j * G
    let commits = feldman_commitments(&coeffs, g);

    (shares, coeffs, commits)
}

pub fn verify_share_with_commitments(
    share: &Share,
    commits: &[JubJubAffine],
    g: JubJubAffine,
) -> bool {
    let xi = Fr::from(share.index);

    // 좌변: y_i * G
    let lhs = g.mul(share.value);

    // 우변: Σ V_j * (x_i^j)
    let mut rhs = JubJub::zero();
    let mut pow_x = Fr::one();
    for vj in commits {
        rhs += vj.mul(pow_x);
        pow_x *= xi;
    }

    lhs.into_affine() == rhs.into_affine()
}

pub fn lagrange_at_zero(i: u64, set: &[u64]) -> Fr {
    let xi = Fr::from(i);
    let mut num = Fr::one(); // 분자
    let mut den = Fr::one(); // 분모

    for &j in set {
        if j == i { continue; }
        let xj = Fr::from(j);
        num *= xj;
        den *= xj - xi;
    }

    num * den.inverse().unwrap()
}

pub fn reconstruct_secret(subset: &[Share]) -> Fr {
    let idxs: Vec<u64> = subset.iter().map(|s| s.index).collect();
    let mut acc = Fr::zero();
    for si in subset {
        let lambda_i = lagrange_at_zero(si.index, &idxs);
        acc += si.value * lambda_i;
    }
    acc
}

pub fn aggregate_pk_from_individual_pks(pks: &[JubJubAffine]) -> JubJubAffine {
    let sum = pks.iter().fold(JubJub::zero(), |acc, p| acc + p.into_group());
    sum.into_affine()
}

pub fn pk_from_commitments(commits: &[JubJubAffine]) -> JubJubAffine {
    assert!(!commits.is_empty(), "no commitments");
    commits[0]
}

pub fn partial_decrypt_share(c1: &JubJubAffine, sk_i: Fr) -> JubJubAffine {
    c1.mul(sk_i).into_affine()
}

pub fn combine_shares_threshold(
    c2: &JubJubAffine,
    indexed_shares: &[(u64, JubJubAffine)], // (index, s_i)
    chosen: &[u64],                         // 사용한 index 집합
) -> JubJubAffine {
    let mut agg = JubJub::zero();
    for &(i, ref s_i) in indexed_shares {
        if !chosen.contains(&i) { continue; }
        let lambda_i = lagrange_at_zero(i, chosen);
        agg += s_i.mul(lambda_i);
    }
    (c2.into_group() - agg).into_affine()
}

pub fn decode_vote(
    msg_point: &JubJubAffine,
    g: &JubJubAffine,
    max_votes: u64, // 득표수 상한선 (예: 100만)
) -> Option<u64> {
    if msg_point.is_zero() {
        return Some(0);
    }
    let mut current_g = g.into_group();
    for k in 1..=max_votes {
        if current_g.into_affine() == *msg_point {
            return Some(k);
        }
        current_g += g.into_group();
    }
    None // max_votes를 초과하는 값을 찾지 못함
}




pub fn ct_sum(cts: &[Ciphertext<JubJub>]) -> elgamal::Ciphertext<JubJub> {
    let mut acc_c1 = JubJub::zero();
    let mut acc_c2 = JubJub::zero();
    for (c1, c2) in cts {
        acc_c1 += c1.into_group();
        acc_c2 += c2.into_group();
    }
    (acc_c1.into_affine(), acc_c2.into_affine())
}

