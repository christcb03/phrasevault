# phrasevault/credentials.py
from dataclasses import dataclass
from typing import Dict, Any
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

@dataclass
class CredentialClaims:
    """Common interface for both JWT and future VC"""
    community: str
    tier: str
    sub: str | None = None
    exp: int | None = None

class CommunityCredential:
    """Phase 1: JWT-based community membership"""
    
    @staticmethod
    def verify(token: str, community_pubkey_pem: str) -> CredentialClaims:
        """Verify JWT signed by community's secp256k1 public key"""
        try:
            claims = jwt.decode(
                token,
                community_pubkey_pem,
                algorithms=["ES256"],
                options={"verify_exp": True}
            )
            return CredentialClaims(
                community=claims.get("community"),
                tier=claims.get("membership_tier", "basic"),
                sub=claims.get("sub"),
                exp=claims.get("exp")
            )
        except jwt.PyJWTError as e:
            raise ValueError(f"Invalid credential: {e}")

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> CredentialClaims:
        """For future VC compatibility — same interface"""
        return CredentialClaims(
            community=data.get("community"),
            tier=data.get("tier", "basic"),
            sub=data.get("sub")
        )
