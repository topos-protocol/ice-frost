use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::utils::Vec;
use crate::{CipherSuite, Error, FrostResult};

/// Utility trait for serializing an ICE-FROST object to a vector of bytes.
pub trait ToBytes<C: CipherSuite>: CanonicalSerialize {
    /// Serialize this to a vector of bytes.
    fn to_bytes(&self) -> FrostResult<C, Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.compressed_size());

        <Self as CanonicalSerialize>::serialize_compressed(self, &mut bytes)
            .map_err(|_| Error::SerializationError)?;

        Ok(bytes)
    }
}

/// Utility trait for deserializing an ICE-FROST object from a slice of bytes.
pub trait FromBytes<C: CipherSuite>: CanonicalDeserialize {
    /// Attempt to deserialize a `T` from a vector of bytes.
    fn from_bytes(bytes: &[u8]) -> FrostResult<C, Self> {
        Self::deserialize_compressed(bytes).map_err(|_| Error::DeserializationError)
    }
}

/// Utility macro for easily deriving `ToBytes` and `FromBytes` traits.
macro_rules! impl_serialization_traits {
    ($type_name:ident <$gen_param:ident>) => {
        impl<$gen_param: crate::CipherSuite> crate::ToBytes<$gen_param> for $type_name<$gen_param> {}
        impl<$gen_param: crate::CipherSuite> crate::FromBytes<$gen_param>
            for $type_name<$gen_param>
        {
        }
    };
}
pub(crate) use impl_serialization_traits;
