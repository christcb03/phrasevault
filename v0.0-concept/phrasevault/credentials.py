# phrasevault/credentials.py
from dataclasses import dataclass
import jwt
from typing import Dict, Any

@dataclass
class CredentialClaims:
    community: str
    tier: str
    sub: str | None = None
    exp: int | None = None

class CommunityCredential:
    """Phase 1: JWT-based community membership (easy to swap for VC later)"""
    
    @staticmethod
    def verify(token: str, community_pubkey_pem: str) -> CredentialClaims:
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
