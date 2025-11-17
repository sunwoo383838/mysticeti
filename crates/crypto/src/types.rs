use serde::{Deserialize, Serialize};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::{EdwardsAffine as JubJubAffine};
use ark_groth16::Proof;

pub mod ark_se_de_as_bytes {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S, T>(val: &T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: CanonicalSerialize,
    {
        let mut bytes = Vec::new();
        val.serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(serde::ser::Error::custom)?;
        serde_bytes::Serialize::serialize(&bytes, s)
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: CanonicalDeserialize,
    {
        let bytes: Vec<u8> = serde_bytes::Deserialize::deserialize(d)?;
        T::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
            .map_err(Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ZKElgamalCiphertext {
    #[serde(with = "ark_se_de_as_bytes")]
    pub c1: JubJubAffine,
    #[serde(with = "ark_se_de_as_bytes")]
    pub c2: JubJubAffine,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VoteTransaction {
    #[serde(with = "ark_se_de_as_bytes")]
    pub proof: Proof<Bls12_381>,
    #[serde(with = "ark_se_de_as_bytes")]
    pub nullifier: Fr,
    pub enc_vote_vec: Vec<ZKElgamalCiphertext>,
}




