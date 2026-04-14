/// W3C Verifiable Credentials v2.0 types for the Resilient Identity PoC.
///
/// Holder Credential: issued to the holder after enrollment.
/// Verifiable Presentation: submitted to verifiers with ZK proof.
use chrono::{
    DateTime,
    Timelike,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};

/// The holder credential, stored locally by the enrolled identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolderCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(rename = "credentialStatus")]
    pub credential_status: CredentialStatus,
}

/// The credential subject contains the identity attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    #[serde(rename = "ageOver18")]
    pub age_over_18: bool,
    pub nationality: String,
    #[serde(rename = "nameHash")]
    pub name_hash: String,
    #[serde(rename = "enrollmentDay")]
    pub enrollment_day: u64,
}

/// On-chain status reference for the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(rename = "contractAddress")]
    pub contract_address: String,
}

/// A verifiable presentation wrapping a credential and a ZK proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<PresentationCredential>,
    pub proof: PresentationProof,
}

/// A stripped-down credential included in the presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: PresentationSubject,
    #[serde(rename = "credentialStatus")]
    pub credential_status: PresentationStatus,
}

/// Minimal subject in a presentation -- only the disclosed predicate hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubject {
    /// Human-readable hint; verifiers MUST rely on the ZK proof instead.
    #[serde(rename = "ageOver18", skip_serializing_if = "Option::is_none")]
    pub age_over_18: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,
}

/// Minimal status reference in a presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

/// ZK proof attached to the verifiable presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub r#type: String,
    pub created: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: String,
    pub nullifier: String,
    #[serde(rename = "externalNullifier")]
    pub external_nullifier: String,
    pub version: u32,
    #[serde(rename = "predicateType")]
    pub predicate_type: u32,
    #[serde(rename = "predicateAttrIndex")]
    pub predicate_attr_index: u32,
    #[serde(rename = "predicateValue")]
    pub predicate_value: u64,
    #[serde(rename = "predicateResult")]
    pub predicate_result: u64,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

const VC_CONTEXT_W3C: &str = "https://www.w3.org/ns/credentials/v2";
const VC_CONTEXT_RIC: &str = "https://example.org/ns/resilient-identity/v1";

fn vc_contexts() -> Vec<String> {
    vec![VC_CONTEXT_W3C.to_string(), VC_CONTEXT_RIC.to_string()]
}

fn vc_types() -> Vec<String> {
    vec![
        "VerifiableCredential".to_string(),
        "ResilientIdentity".to_string(),
    ]
}

/// Format a DID for the enrollment contract: `did:pkh:eip155:{chain_id}:{address}`
pub fn issuer_did(chain_id: u64, contract_address: &str) -> String {
    format!("did:pkh:eip155:{chain_id}:{contract_address}")
}

/// Truncate a timestamp to minute granularity (seconds and sub-seconds zeroed).
pub fn truncate_to_minute(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(dt)
}

/// Format a timestamp as ISO 8601 truncated to minute: `2026-03-31T00:00Z`
pub fn format_timestamp(dt: DateTime<Utc>) -> String {
    let t = truncate_to_minute(dt);
    t.format("%Y-%m-%dT%H:%MZ").to_string()
}

/// Build the holder credential issued after enrollment.
pub fn build_holder_credential(
    chain_id: u64,
    enrollment_contract: &str,
    identity_tree_contract: &str,
    now: DateTime<Utc>,
    subject: CredentialSubject,
) -> HolderCredential {
    HolderCredential {
        context: vc_contexts(),
        r#type: vc_types(),
        issuer: issuer_did(chain_id, enrollment_contract),
        valid_from: format_timestamp(now),
        credential_subject: subject,
        credential_status: CredentialStatus {
            id: format!("urn:ric:{chain_id}:{identity_tree_contract}"),
            r#type: "MerkleTreeInclusion".to_string(),
            chain_id,
            contract_address: identity_tree_contract.to_string(),
        },
    }
}

/// Build a verifiable presentation wrapping a credential and ZK proof.
pub fn build_verifiable_presentation(
    credential: PresentationCredential,
    proof: PresentationProof,
) -> VerifiablePresentation {
    VerifiablePresentation {
        context: vc_contexts(),
        r#type: vec!["VerifiablePresentation".to_string()],
        verifiable_credential: vec![credential],
        proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_issuer_did() {
        let did = issuer_did(1, "0xabcdef");
        assert_eq!(did, "did:pkh:eip155:1:0xabcdef");
    }

    #[test]
    fn test_truncate_to_minute() {
        let dt = Utc.with_ymd_and_hms(2026, 3, 31, 14, 30, 45).unwrap();
        let truncated = truncate_to_minute(dt);
        assert_eq!(truncated.second(), 0);
        assert_eq!(truncated.nanosecond(), 0);
    }

    #[test]
    fn test_format_timestamp() {
        let dt = Utc.with_ymd_and_hms(2026, 3, 31, 14, 30, 45).unwrap();
        let s = format_timestamp(dt);
        assert_eq!(s, "2026-03-31T14:30Z");
    }

    #[test]
    fn test_holder_credential_roundtrip() {
        let dt = Utc.with_ymd_and_hms(2026, 3, 31, 0, 0, 0).unwrap();
        let subject = CredentialSubject {
            age_over_18: true,
            nationality: "840".to_string(),
            name_hash: "0xabc".to_string(),
            enrollment_day: 20178,
        };
        let cred = build_holder_credential(1, "0xcontract", "0xtree", dt, subject);

        let json = serde_json::to_string_pretty(&cred).unwrap();
        let parsed: HolderCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.issuer, "did:pkh:eip155:1:0xcontract");
        assert_eq!(parsed.credential_subject.age_over_18, true);
        assert_eq!(parsed.credential_status.r#type, "MerkleTreeInclusion");
    }

    #[test]
    fn test_verifiable_presentation_roundtrip() {
        let cred = PresentationCredential {
            context: vc_contexts(),
            r#type: vc_types(),
            issuer: issuer_did(1, "0xcontract"),
            valid_from: "2026-03-31T00:00Z".to_string(),
            credential_subject: PresentationSubject {
                age_over_18: Some(true),
                nationality: None,
            },
            credential_status: PresentationStatus {
                id: "urn:ric:1:0xtree".to_string(),
                r#type: "MerkleTreeInclusion".to_string(),
            },
        };
        let proof = PresentationProof {
            r#type: "ZKMerkleInclusionProof".to_string(),
            created: "2026-04-04T12:00Z".to_string(),
            proof_purpose: "authentication".to_string(),
            verification_method: "did:pkh:eip155:1:0xtree".to_string(),
            chain_id: 1,
            merkle_root: "0xdeadbeef".to_string(),
            nullifier: "0x1234".to_string(),
            external_nullifier: "0x5678".to_string(),
            version: 1,
            predicate_type: 1,
            predicate_attr_index: 0,
            predicate_value: 0,
            predicate_result: 1,
            proof_value: "0xproof".to_string(),
        };
        let vp = build_verifiable_presentation(cred, proof);

        let json = serde_json::to_string_pretty(&vp).unwrap();
        let parsed: VerifiablePresentation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.r#type, vec!["VerifiablePresentation"]);
        assert_eq!(parsed.proof.r#type, "ZKMerkleInclusionProof");
        assert_eq!(parsed.verifiable_credential.len(), 1);
    }
}
