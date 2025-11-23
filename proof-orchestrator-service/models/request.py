from pydantic import BaseModel, Field
from typing import List

class ProofGenerationRequest(BaseModel):
    root_hash: str = Field(..., min_length=64, max_length=64)
    banned_list: List[str] = Field(..., min_items=1)

