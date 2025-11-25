use std::ops::{Mul, Neg};
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme};
use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::encryption::elgamal::{Ciphertext, PublicKey};
use ark_crypto_primitives::encryption::elgamal::constraints::{OutputVar, PublicKeyVar};
use ark_crypto_primitives::merkle_tree::{Config, IdentityDigestConverter, Path};
use ark_crypto_primitives::merkle_tree::constraints::{ConfigGadget, PathVar};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ec::pairing::Pairing;
use ark_r1cs_std::fields::fp::FpVar;
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine, EdwardsProjective as JubJub, Fr as JubJubFr};
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ff::{BigInteger, Field, PrimeField, ToConstraintField, Zero};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::r1cs::Result as R1CSResult;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use ark_std::{One, UniformRand};
use rayon::prelude::*;
use thiserror::Error;
use crate::types::ZKElgamalCiphertext;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error(transparent)]
    Crypto(#[from] ark_crypto_primitives::Error),

    #[error(transparent)]
    Synthesis(#[from] SynthesisError),
}

type ZkResult<T> = Result<T, ZkError>;

#[allow(dead_code)]
pub struct MerkleTreePoseidonConfig;
impl Config for MerkleTreePoseidonConfig {
    type Leaf = [Fr];
    type LeafDigest = Fr;
    type LeafInnerDigestConverter = IdentityDigestConverter<Fr>;
    type InnerDigest = Fr;
    type LeafHash = CRH<Fr>;
    type TwoToOneHash = TwoToOneCRH<Fr>;
}

#[allow(dead_code)]
struct MerkleTreePoseidonConfigGadget;
impl ConfigGadget<MerkleTreePoseidonConfig, Fr> for MerkleTreePoseidonConfigGadget {
    type Leaf = [FpVar<Fr>];
    type LeafDigest = FpVar<Fr>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Fr>>;
    type InnerDigest = FpVar<Fr>;
    type LeafHash = CRHGadget<Fr>;
    type TwoToOneHash = TwoToOneCRHGadget<Fr>;
}

#[allow(dead_code)]
#[derive(Clone)]
struct VoteCircuit {
    // Witness
    cred: Fr,
    merkle_path: Path<MerkleTreePoseidonConfig>,
    vote_bits: Vec<bool>,
    encryption_rand: JubJubFr,

    // Public Input
    election_id: Fr,
    voter_set_root: Fr,
    nullifier: Fr,
    enc_vote_vec: Vec<Ciphertext<JubJub>>,
    committee_pk: PublicKey<JubJub>,
    elgamal_generator: JubJubAffine,

    // Const
    params_leaf: PoseidonConfig<Fr>,
    params_merkle: PoseidonConfig<Fr>,
    params_nullifier: PoseidonConfig<Fr>,
    nf_constant: Fr,
}

impl ConstraintSynthesizer<Fr> for VoteCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> R1CSResult<()> {

        let params_leaf_var =
            CRHParametersVar::new_constant(cs.clone(), self.params_leaf)?;
        let params_merkle_var =
            CRHParametersVar::new_constant(cs.clone(), self.params_merkle)?;
        let params_nullifier_var =
            CRHParametersVar::new_constant(cs.clone(), self.params_nullifier)?;
        let nf_constant_var= FpVar::new_constant(cs.clone(), self.nf_constant)?;


        let pk_var =
            PublicKeyVar::<JubJub, EdwardsVar>::new_constant(ns!(cs, "pk"), self.committee_pk)?;
        let g_var: EdwardsVar =
            <EdwardsVar as AllocVar<JubJubAffine, Fr>>::new_constant(cs.clone(), self.elgamal_generator)?;
        let eid_var = FpVar::new_constant(ns!(cs, "eid"), self.election_id)?;

        let mut enc_vote_vec_vars: Vec<OutputVar<JubJub, EdwardsVar>> = Vec::with_capacity(self.enc_vote_vec.len());
        for ct in self.enc_vote_vec.iter() {
            enc_vote_vec_vars.push(
                OutputVar::<JubJub, EdwardsVar>::new_input(cs.clone(), || Ok(ct.clone()))?
            );
        }
        let root_var      = FpVar::new_input(ns!(cs, "root"), || Ok(self.voter_set_root))?;
        let nullifier_var = FpVar::new_input(ns!(cs, "nullifier"), || Ok(self.nullifier))?;

        let cred_var  = FpVar::new_witness(ns!(cs, "cred"),  || Ok(self.cred))?;
        let r_bits = Vec::<Boolean<Fr>>::new_witness(ns!(cs, "elgamal_r_bits"), || {
            Ok(self.encryption_rand.into_bigint().to_bits_le())
        })?;
        let mut vote_bits_vars: Vec<Boolean<Fr>> = Vec::with_capacity(self.vote_bits.len());
        for (_, &b) in self.vote_bits.iter().enumerate() {
            let bit = Boolean::new_witness(ns!(cs, "vote_bit_{}"), || Ok(b))?;
            vote_bits_vars.push(bit);
        }
        let path_var = PathVar::<MerkleTreePoseidonConfig, Fr, MerkleTreePoseidonConfigGadget>
        ::new_witness(ns!(cs, "merkle_path"), || Ok(&self.merkle_path))?;

        // 회로
        let leaf_preimage: [FpVar<Fr>; 2] = [cred_var.clone(), eid_var.clone()];
        let ok = path_var.verify_membership(
            &params_leaf_var,
            &params_merkle_var,
            &root_var,
            &leaf_preimage[..],
        )?;
        ok.enforce_equal(&Boolean::TRUE)?;

        let null_inputs = vec![nf_constant_var, cred_var];
        let computed_null = CRHGadget::evaluate(&params_nullifier_var, &null_inputs)?;
        computed_null.enforce_equal(&nullifier_var)?;

        let mut sum = FpVar::<Fr>::zero();
        for bit in &vote_bits_vars {
            let term = bit.select(&FpVar::one(), &FpVar::zero())?;
            sum += term;
        }
        sum.enforce_equal(&FpVar::one())?;

        let rg_var  = g_var.scalar_mul_le(r_bits.iter())?;
        let rpk_var = pk_var.pk.scalar_mul_le(r_bits.iter())?;

        for (bit, ct) in vote_bits_vars.iter().zip(enc_vote_vec_vars.iter()) {
            let mg = g_var.scalar_mul_le(core::iter::once(bit))?;
            let expected_c2 = &rpk_var + &mg;

            ct.c1.enforce_equal(&rg_var)?;
            ct.c2.enforce_equal(&expected_c2)?;
        }
        Ok(())
    }
}

const FULL_ROUNDS: usize    = 8;
const PARTIAL_ROUNDS: usize = 31;
const ALPHA: u64          = 17;
const RATE: usize           = 2;
const CAPACITY: usize       = 1;

const DOMAIN_ID_MERKLE: u64    = 0;
const DOMAIN_ID_NULLIFIER: u64 = 1;
const DOMAIN_ID_LEAF: u64      = 2;

pub fn setup_poseidon_params() -> (PoseidonConfig<Fr>, PoseidonConfig<Fr>, PoseidonConfig<Fr>) {

    let (ark_merkle, mds_merkle) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, DOMAIN_ID_MERKLE
    );
    let params_merkle = PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds_merkle, ark_merkle, RATE, CAPACITY);

    let (ark_null, mds_null) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, DOMAIN_ID_NULLIFIER
    );
    let params_nullifier = PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds_null, ark_null, RATE, CAPACITY);

    let (ark_leaf, mds_leaf) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64, RATE, FULL_ROUNDS as u64, PARTIAL_ROUNDS as u64, DOMAIN_ID_LEAF
    );
    let params_leaf = PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds_leaf, ark_leaf, RATE, CAPACITY);

    (params_leaf, params_merkle, params_nullifier)

}

pub fn setup(
    num_candidates: usize,
    merkle_height: usize,
    committee_pk: PublicKey<JubJub>,
    elgamal_generator: JubJubAffine,
    election_id: Fr,
) -> ZkResult<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {

    assert!(merkle_height >= 1, "merkle_height must be >= 1 for this setup path");

    let (params_leaf, params_merkle, params_nullifier) = setup_poseidon_params();
    let nf_constant = Fr::from_le_bytes_mod_order(b"NF");
    let mut rng = StdRng::from_entropy();

    let leaf = <CRH<Fr> as CRHScheme>::evaluate(&params_leaf, [Fr::zero(), Fr::zero()])?;
    let auth_path: Vec<Fr> = vec![Fr::zero(); merkle_height.saturating_sub(1)];
    let mut cur = <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::evaluate(
        &params_merkle,
        leaf,
        Fr::zero(),
    )?;
    for sib in auth_path.iter().cloned() {
        cur = <TwoToOneCRH<Fr> as TwoToOneCRHScheme>::evaluate(&params_merkle, cur, sib)?;
    }
    let root = cur;
    let path = Path::<MerkleTreePoseidonConfig> {
        leaf_sibling_hash: Fr::zero(),
        leaf_index: 0,
        auth_path,
    };

    let circuit_blank = VoteCircuit {
        cred: Fr::zero(),
        merkle_path: path,
        vote_bits: vec![false; num_candidates],
        encryption_rand: JubJubFr::zero(),

        election_id,
        voter_set_root: root,
        nullifier: Fr::zero(),
        enc_vote_vec: vec![Ciphertext::<JubJub>::default(); num_candidates],
        committee_pk,
        elgamal_generator,

        params_leaf,
        params_merkle,
        params_nullifier,
        nf_constant,
    };

    let (pk, vk) = Groth16::<Bls12_381, LibsnarkReduction>::setup(circuit_blank, &mut rng)?;
    Ok((pk, vk))
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bls12_381>,

    cred: &[u8],
    merkle_path: Path<MerkleTreePoseidonConfig>,
    vote_vec: Vec<u8>,
    encryption_rand: JubJubFr,

    election_id: &str,
    voter_set_root: Fr,
    enc_vote_vec: Vec<Ciphertext<JubJub>>,

    committee_pk: PublicKey<JubJub>,
    elgamal_generator: JubJubAffine,
    rng: &mut R,
) -> R1CSResult<(Proof<Bls12_381>, Vec<Fr>)> {
    if enc_vote_vec.len() != vote_vec.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    let (params_leaf, params_merkle, params_nullifier) = setup_poseidon_params();
    let nf_constant = Fr::from_le_bytes_mod_order(b"NF");
    let vote_bits = vote_vec.into_iter().map(|byte| byte != 0).collect();
    let cred_fr = Fr::from_le_bytes_mod_order(cred);
    let nullifier = CRH::evaluate(&params_nullifier, [nf_constant, cred_fr]).unwrap();

    let circuit = VoteCircuit {
        cred: Fr::from_le_bytes_mod_order(cred),
        merkle_path,
        vote_bits,
        encryption_rand,

        election_id: Fr::from_le_bytes_mod_order(election_id.as_bytes()),
        voter_set_root,
        nullifier,
        enc_vote_vec: enc_vote_vec.clone(),
        committee_pk,
        elgamal_generator,

        params_leaf,
        params_merkle,
        params_nullifier,
        nf_constant,
    };

    let proof = Groth16::<Bls12_381, LibsnarkReduction>::prove(pk, circuit, rng)?;
    let mut public_inputs = Vec::<Fr>::with_capacity(4 * enc_vote_vec.len() + 2);
    for enc_vote in &enc_vote_vec {
        public_inputs.extend(
            ToConstraintField::<Fr>::to_field_elements(&enc_vote.0).unwrap()
        );
        public_inputs.extend(
            ToConstraintField::<Fr>::to_field_elements(&enc_vote.1).unwrap()
        );
    }
    public_inputs.push(voter_set_root);
    public_inputs.push(nullifier);

    Ok((proof, public_inputs))
}

pub fn verify(
    vk: &VerifyingKey<Bls12_381>,
    proof: &Proof<Bls12_381>,
    enc_vote_vec: &[ZKElgamalCiphertext],
    voter_set_root: Fr,
    nullifier: Fr,
) -> R1CSResult<bool> {
    let public_inputs = prepare_public_inputs(enc_vote_vec, voter_set_root, nullifier).unwrap();

    let result = Groth16::<Bls12_381, LibsnarkReduction>::verify(
        vk,
        &public_inputs,
        proof
    )?;
    Ok(result)
}

pub fn prepare_public_inputs(
    enc_vote_vec: &[ZKElgamalCiphertext],
    voter_set_root: Fr,
    nullifier: Fr,
) -> R1CSResult<Vec<Fr>> {
    let mut public_inputs = Vec::with_capacity(4 * enc_vote_vec.len() + 2);

    for ct in enc_vote_vec {
        public_inputs.extend(
            ToConstraintField::<Fr>::to_field_elements(&ct.c1)
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
        public_inputs.extend(
            ToConstraintField::<Fr>::to_field_elements(&ct.c2)
                .ok_or(SynthesisError::AssignmentMissing)?,
        );
    }
    public_inputs.push(voter_set_root);
    public_inputs.push(nullifier);

    Ok(public_inputs)
}

pub fn batch_verify(
    pvk: &PreparedVerifyingKey<Bls12_381>,
    proofs: &[Proof<Bls12_381>],
    public_inputs: &[Vec<Fr>],
) -> R1CSResult<bool> {
    // 1. 기본 검증
    if proofs.len() != public_inputs.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    if proofs.is_empty() {
        return Ok(true);
    }

    let mut rng = StdRng::from_entropy();

    // 2. 랜덤 스칼라 r_i 생성
    let randomizers: Vec<Fr> = (0..proofs.len())
        .map(|_| Fr::rand(&mut rng))
        .collect();

    // total_r = sum(r_i)
    let total_r: Fr = randomizers.iter().copied().sum();

    // 3. Public Input 스칼라 집계 (Scalar Aggregation)
    //    열(column) 단위로 합산: sum(r_i * x_ij)
    let num_inputs = public_inputs[0].len();
    let aggregated_inputs: Vec<Fr> = (0..num_inputs)
        .into_par_iter()
        .map(|j| {
            public_inputs
                .iter()
                .zip(&randomizers)
                .map(|(inputs, r)| inputs[j] * *r)
                .sum()
        })
        .collect();

    // 4. L_sum 계산 (prepare_inputs 재활용 + G0 보정)
    //    L_sum = G_0 * (sum(r) - 1) + prepare_inputs(sum(r*x))
    //    (참고: prepare_inputs는 내부적으로 G_0를 한 번 더하므로, 보정값은 total_r - 1 임)
    let mut g_ic_proj = Groth16::<Bls12_381, LibsnarkReduction>::prepare_inputs(pvk, &aggregated_inputs)?;
    let g0 = pvk.vk.gamma_abc_g1[0];
    let adjustment = g0.mul(total_r - Fr::one());
    let g_ic_prepared: <Bls12_381 as Pairing>::G1Prepared = (g_ic_proj + adjustment).into_affine().into();
    // 5. C_sum 계산: sum(r_i * C_i) (MSM 활용)
    let c_points: Vec<_> = proofs.iter().map(|p| p.c).collect();
    let c_sum = <Bls12_381 as Pairing>::G1::msm(&c_points, &randomizers).unwrap();

    // 6. A_i 처리: sum(e(r_i * A_i, B_i))
    //    A_i에 r_i를 곱함
    let scaled_a: Vec<_> = proofs
        .par_iter()
        .zip(&randomizers)
        .map(|(p, r)| p.a.mul(*r).into_affine())
        .collect();

    // 7. Multi-Miller Loop 수행
    //    좌변 = prod( e(rA, B) ) * e(L_sum, -gamma) * e(C_sum, -delta)
    let ml_result = Bls12_381::multi_miller_loop(
        scaled_a.iter()
            .map(|a| <Bls12_381 as Pairing>::G1Prepared::from(*a))
            .chain(std::iter::once(g_ic_prepared)) // 이미 Prepared
            .chain(std::iter::once(<Bls12_381 as Pairing>::G1Prepared::from(c_sum.into_affine()))),

        proofs.iter()
            .map(|p| <Bls12_381 as Pairing>::G2Prepared::from(p.b)) // [핵심] 변환 추가
            .chain(std::iter::once(pvk.gamma_g2_neg_pc.clone()))
            .chain(std::iter::once(pvk.delta_g2_neg_pc.clone())),
    );

    // Final Exponentiation으로 GT 원소로 변환
    let lhs = Bls12_381::final_exponentiation(ml_result).ok_or(SynthesisError::UnexpectedIdentity)?.0;

    // 8. 우변 계산: (alpha * beta)^(sum r_i)
    //    pvk.alpha_g1_beta_g2는 이미 e(alpha, beta) 값임
    let rhs = pvk.alpha_g1_beta_g2.pow(total_r.into_bigint());

    // 9. 비교: 좌변 == 우변
    Ok(lhs == rhs)
}




