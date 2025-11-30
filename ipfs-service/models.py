from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ProofMapping(db.Model):
    __tablename__ = "proof_mappings"
    
    id = db.Column(db.Integer, primary_key=True)
    composite_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ipfs_cid = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<ProofMapping(composite_hash={self.composite_hash}, cid={self.ipfs_cid})>"
    
    def to_dict(self):
        return {
            "composite_hash": self.composite_hash,
            "ipfs_cid": self.ipfs_cid,
            "created_at": self.created_at.isoformat()
        }

