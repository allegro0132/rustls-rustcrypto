#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use super::{DecryptBufferAdapter, EncryptBufferAdapter};

use aead::AeadInOut;
use crypto_common::{KeyInit, KeySizeUser};
use paste::paste;
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

#[cfg(feature = "tls12")]
use {
    aead::AeadCore,
    crypto_common::typenum::Unsigned,
    rustls::crypto::cipher::{Iv, KeyBlockShape, Tls12AeadAlgorithm},
};

#[cfg(feature = "tls12")]
const TLS12_GCM_EXPLICIT_NONCE_LEN: usize = 8;

#[cfg(feature = "tls12")]
const TLS12_GCM_OVERHEAD: usize = TLS12_GCM_EXPLICIT_NONCE_LEN + 16;

// Own the operation across scheduler polls; no borrowed record storage escapes.
#[cfg(feature = "eip197-backend")]
struct PendingGcm {
    operation: Box<dyn aes_gcm::backend::Operation>,
    typ: ContentType,
    version: ProtocolVersion,
    explicit: Option<[u8; 8]>,
}

#[cfg(feature = "eip197-backend")]
struct GcmOutput(aes_gcm::backend::Output);
#[cfg(feature = "eip197-backend")]
impl AsRef<[u8]> for GcmOutput {fn as_ref(&self)->&[u8]{self.0.as_ref()}}
#[cfg(feature = "eip197-backend")]
impl AsMut<[u8]> for GcmOutput {fn as_mut(&mut self)->&mut [u8]{self.0.as_mut()}}
#[cfg(feature = "eip197-backend")]
impl cipher::PayloadBuffer for GcmOutput {}

#[cfg(feature = "eip197-backend")]
impl cipher::PendingEncryption for PendingGcm {
    fn poll(&mut self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<OutboundOpaqueMessage, rustls::Error>> {
        use core::task::Poll;
        match self.operation.poll_output(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(rustls::Error::EncryptError)),
            Poll::Ready(Ok((mut data, tag))) => {
                if let Some(explicit)=self.explicit { data.prepend(&explicit); }
                data.append(&tag);
                data.prepend(&[0;5]);
                Poll::Ready(PrefixedPayload::from_buffer(Box::new(GcmOutput(data)))
                    .map(|payload|OutboundOpaqueMessage::new(self.typ,self.version,payload)))
            }
        }
    }
}

#[cfg(feature = "eip197-backend")]
struct PendingGcmDecryption {
    operation: Option<Box<dyn aes_gcm::backend::Operation>>,
    typ: ContentType,
    version: ProtocolVersion,
    tls13: bool,
}
#[cfg(feature = "eip197-backend")]
impl cipher::PendingDecryption for PendingGcmDecryption {
    fn poll_into(&mut self, cx: &mut core::task::Context<'_>, dst: &mut [u8])
        -> core::task::Poll<Result<(ContentType, ProtocolVersion, usize), rustls::Error>> {
        use core::task::{ready, Poll};
        let operation = self.operation.as_mut().ok_or(rustls::Error::DecryptError)?;
        let result = ready!(operation.poll_output(cx));
        self.operation = None;
        let (mut data, _) = result.map_err(|_| rustls::Error::DecryptError)?;
        let (typ, version, len) = if self.tls13 {
            let plain = InboundOpaqueMessage::new(self.typ, self.version, data.as_mut())
                .into_tls13_unpadded_message()?;
            (plain.typ, plain.version, plain.payload.len())
        } else {
            (self.typ, self.version, data.as_ref().len())
        };
        let out = dst.get_mut(..len).ok_or(rustls::Error::DecryptError)?;
        data.copy_prefix_to(out).map_err(|_| rustls::Error::DecryptError)?;
        Poll::Ready(Ok((typ, version, len)))
    }
    fn poll(&mut self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<cipher::OwnedPlaintext, rustls::Error>> {
        use core::task::Poll;
        let Some(operation) = self.operation.as_mut() else { return Poll::Ready(Err(rustls::Error::DecryptError)); };
        let result = match operation.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.operation = None;
        Poll::Ready(result.map_err(|_|rustls::Error::DecryptError).and_then(|(data,_)| {
            let mut plain = cipher::OwnedPlaintext { typ:self.typ, version:self.version, payload:data };
            if self.tls13 {
                let (typ,version,len) = {
                    let message = InboundOpaqueMessage::new(plain.typ,plain.version,&mut plain.payload)
                        .into_tls13_unpadded_message()?;
                    (message.typ,message.version,message.payload.len())
                };
                plain.typ=typ; plain.version=version; plain.payload.truncate(len);
            }
            Ok(plain)
        }))
    }
}

macro_rules! impl_gcm_tls13 {
    ($name: ident, $aead: ty, $overhead: expr) => {
        paste! {
            pub struct [<Tls13 $name>];

            impl Tls13AeadAlgorithm for [<Tls13 $name>] {
                fn encrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageEncrypter> {
                    Box::new([<Tls13Cipher $name>](
                        $aead::new_from_slice(key.as_ref()).unwrap(),
                        iv,
                    ))
                }

                fn decrypter(&self, key: AeadKey, iv: cipher::Iv) -> Box<dyn MessageDecrypter> {
                    Box::new([<Tls13Cipher $name>](
                        $aead::new_from_slice(key.as_ref()).unwrap(),
                        iv,
                    ))
                }

                fn key_len(&self) -> usize {
                    $aead::key_size()
                }
                fn extract_keys(
                    &self,
                    key: AeadKey,
                    iv: cipher::Iv,
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
                }
            }

            struct [<Tls13Cipher $name>]($aead, cipher::Iv);

            impl MessageEncrypter for [<Tls13Cipher $name>] {
                #[cfg(feature = "eip197-backend")]
                fn start_encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Box<dyn cipher::PendingEncryption> {
                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(self.encrypted_payload_len(m.payload.len()));
                    let mut data = alloc::vec::Vec::with_capacity(m.payload.len() + 22);
                    m.payload.copy_to_vec(&mut data);
                    data.extend_from_slice(&m.typ.to_array());
                    Box::new(PendingGcm {
                        operation: self.0.start_encrypt_owned(nonce, aad.to_vec(), data),
                        typ: ContentType::ApplicationData,
                        version: ProtocolVersion::TLSv1_2,
                        explicit: None,
                    })
                }
                fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let total_len = self.encrypted_payload_len(m.payload.len());
                    let mut payload = PrefixedPayload::with_capacity(total_len);

                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(total_len);
                    payload.extend_from_chunks(&m.payload);
                    payload.extend_from_slice(&m.typ.to_array());

                    self.0
                        .encrypt_in_place(&nonce.into(), &aad, &mut EncryptBufferAdapter(&mut payload))
                        .map_err(|_| rustls::Error::EncryptError)
                        .map(|_| OutboundOpaqueMessage::new(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_2,
                            payload,
                        ))
                }

                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + 1 + $overhead
                }
            }

            impl MessageDecrypter for [<Tls13Cipher $name>] {
                #[cfg(feature = "eip197-backend")]
                fn start_decrypt(&mut self, m: InboundOpaqueMessage<'_>, seq: u64) -> Box<dyn cipher::PendingDecryption> {
                    let operation = if m.payload.len() < 16 { None } else {
                        let split = m.payload.len() - 16;
                        let tag = m.payload[split..].try_into().unwrap();
                        Some(self.0.start_decrypt_owned(cipher::Nonce::new(&self.1,seq).0,
                            cipher::make_tls13_aad(m.payload.len()).to_vec(),m.payload[..split].to_vec(),tag))
                    };
                    Box::new(PendingGcmDecryption {operation,typ:m.typ,version:m.version,tls13:true})
                }
                fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    let payload = &mut m.payload;
                    let nonce = cipher::Nonce::new(&self.1, seq).0;
                    let aad = cipher::make_tls13_aad(payload.len());

                    self.0
                        .decrypt_in_place(&nonce.into(), &aad, &mut DecryptBufferAdapter(payload))
                        .map_err(|_| rustls::Error::DecryptError)?;

                    m.into_tls13_unpadded_message()
                }
            }

        }
    };
}

#[cfg(feature = "tls12")]
macro_rules! impl_gcm_tls12 {
    ($name: ident, $aead: ty, $nonce: expr, $overhead: expr) => {
        paste! {
            #[cfg(feature = "tls12")]
            pub struct [<Tls12 $name>];

            #[cfg(feature = "tls12")]
            impl Tls12AeadAlgorithm for [<Tls12 $name>] {
                fn encrypter(&self, key: AeadKey, write_iv: &[u8], explicit: &[u8]) -> Box<dyn MessageEncrypter> {
                    Box::new([<Tls12Cipher $name Encrypter>](
                        $aead::new_from_slice(key.as_ref()).unwrap(),
                        {
                            let mut iv: [u8; 12] = [0; 12];
                            iv[..4].copy_from_slice(write_iv);
                            iv[4..].copy_from_slice(explicit);
                            iv
                        },
                    ))
                }

                fn decrypter(&self, dec_key: AeadKey, dec_iv: &[u8]) -> Box<dyn MessageDecrypter> {
                    Box::new([<Tls12Cipher $name Decrypter>](
                        $aead::new_from_slice(dec_key.as_ref()).unwrap(),
                        dec_iv.try_into().unwrap(),
                    ))
                }

                fn key_block_shape(&self) -> KeyBlockShape {
                    KeyBlockShape {
                        enc_key_len:        $aead::key_size(),
                        fixed_iv_len:       4,
                        explicit_nonce_len: 8,
                    }
                }

                fn extract_keys(
                    &self,
                    key: AeadKey,
                    iv: &[u8],
                    _explicit: &[u8],
                ) -> Result<ConnectionTrafficSecrets, cipher::UnsupportedOperationError> {
                    Ok(ConnectionTrafficSecrets::Aes128Gcm {
                        key,
                        iv: Iv::new(iv[..].try_into().unwrap()),
                    })
                }
            }

            #[cfg(feature = "tls12")]
            struct [<Tls12Cipher $name Encrypter>]($aead, [u8; 12]);

            #[cfg(feature = "tls12")]
            impl MessageEncrypter for [<Tls12Cipher $name Encrypter>] {
                #[cfg(feature = "eip197-backend")]
                fn start_encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Box<dyn cipher::PendingEncryption> {
                    let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());
                    let mut data = alloc::vec::Vec::with_capacity(m.payload.len() + 29);
                    m.payload.copy_to_vec(&mut data);
                    Box::new(PendingGcm {
                        operation: self.0.start_encrypt_owned(nonce, aad.to_vec(), data),
                        typ: m.typ,
                        version: m.version,
                        explicit: Some(nonce[4..].try_into().unwrap()),
                    })
                }
                fn encrypt(&mut self, m: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
                    let total_len = self.encrypted_payload_len(m.payload.len());
                    let mut payload = PrefixedPayload::with_capacity(total_len);

                    let nonce = cipher::Nonce::new(&self.1.into(), seq).0;
                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());
                    payload.extend_from_slice(&nonce.as_ref()[4..]); // explicit
                    payload.extend_from_chunks(&m.payload);

                    self.0
                        .encrypt_inout_detached(&nonce.into(), &aad, (&mut payload.as_mut()[$nonce..]).into())
                        .map(|tag| payload.extend(tag.as_ref() as &[u8]))
                        .map_err(|_| rustls::Error::EncryptError)
                        .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
                }
                fn encrypted_payload_len(&self, payload_len: usize) -> usize {
                    payload_len + $nonce + <$aead as AeadCore>::TagSize::USIZE
                }
            }

            #[cfg(feature = "tls12")]
            struct [<Tls12Cipher $name Decrypter>]($aead, [u8; 4]);

            #[cfg(feature = "tls12")]
            impl MessageDecrypter for [<Tls12Cipher $name Decrypter>] {
                #[cfg(feature = "eip197-backend")]
                fn start_decrypt(&mut self, m: InboundOpaqueMessage<'_>, seq: u64) -> Box<dyn cipher::PendingDecryption> {
                    let operation = if m.payload.len() < $overhead { None } else {
                        let split = m.payload.len() - 16;
                        let tag = m.payload[split..].try_into().unwrap();
                        let mut nonce = [0;12];
                        nonce[..4].copy_from_slice(&self.1);
                        nonce[4..].copy_from_slice(&m.payload[..$nonce]);
                        Some(self.0.start_decrypt_owned(nonce,
                            cipher::make_tls12_aad(seq,m.typ,m.version,m.payload.len()-$overhead).to_vec(),
                            m.payload[$nonce..split].to_vec(),tag))
                    };
                    Box::new(PendingGcmDecryption {operation,typ:m.typ,version:m.version,tls13:false})
                }
                fn decrypt<'a>(&mut self, mut m: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
                    type TagSize = <$aead as AeadCore>::TagSize;

                    let payload = &m.payload;

                    if payload.len() < $overhead {
                        return Err(rustls::Error::DecryptError);
                    }

                    let nonce: aead::Nonce<$aead> = {
                        let mut nonce = [0u8; 12];
                        nonce[..4].copy_from_slice(&self.1); // dec_iv
                        nonce[4..].copy_from_slice(&payload[..$nonce]);
                        nonce.into()
                    };

                    let aad = cipher::make_tls12_aad(seq, m.typ, m.version, payload.len() - $overhead);

                    let payload = &mut m.payload;
                    let tag_pos = {
                        let payload = &mut payload[$nonce..];
                        let tag_pos = payload.len() - TagSize::to_usize();
                        let (msg, tag) = payload.split_at_mut(tag_pos);

                        let tag = aes_gcm::Tag::<TagSize>::try_from(&*tag)
                            .map_err(|_| rustls::Error::DecryptError)?;
                        self.0
                            .decrypt_inout_detached(&nonce, &aad, msg.into(), &tag)
                            .map_err(|_| rustls::Error::DecryptError)?;
                        tag_pos
                    };

                    // We defer the truncation to here, because we may inadvertently shifted the
                    // original data if the decryption failed. Another way to avoid this is
                    // to clone the payload slice starting after the explicit nonce,
                    // but this will cause an additional cloning and copying
                    payload.rotate_left($nonce);
                    payload.truncate(tag_pos);
                    Ok(m.into_plain_message())
                }
            }
        }
    };
}

impl_gcm_tls13! {Aes128Gcm, aes_gcm::Aes128Gcm, 16}
impl_gcm_tls13! {Aes256Gcm, aes_gcm::Aes256Gcm, 16}

#[cfg(feature = "tls12")]
impl_gcm_tls12! {Aes128Gcm, aes_gcm::Aes128Gcm, TLS12_GCM_EXPLICIT_NONCE_LEN, TLS12_GCM_OVERHEAD}

#[cfg(feature = "tls12")]
impl_gcm_tls12! {Aes256Gcm, aes_gcm::Aes256Gcm, TLS12_GCM_EXPLICIT_NONCE_LEN, TLS12_GCM_OVERHEAD}
