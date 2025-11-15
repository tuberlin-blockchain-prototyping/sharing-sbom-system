import base64
import logging
from flask import Blueprint, request, jsonify
from models import db, ProofMapping
from ipfs_client import ipfs_client
from utils import normalize_sbom_hash

logger = logging.getLogger(__name__)

bp = Blueprint("api", __name__)

@bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "ipfs_connected": ipfs_client.is_connected()
    })

@bp.route("/store", methods=["POST"])
def store():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    proof_base64 = data.get("proof")
    sbom_hash_raw = data.get("sbom_hash")
    
    if not proof_base64:
        return jsonify({"error": "Missing 'proof' field"}), 400
    if not sbom_hash_raw:
        return jsonify({"error": "Missing 'sbom_hash' field"}), 400
    
    try:
        proof_bytes = base64.b64decode(proof_base64)
    except Exception as e:
        logger.warning(f"Invalid base64 proof: {e}")
        return jsonify({"error": f"Invalid base64 proof: {e}"}), 400
    
    try:
        sbom_hash = normalize_sbom_hash(sbom_hash_raw)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    existing = ProofMapping.query.filter_by(sbom_hash=sbom_hash).first()
    if existing:
        logger.info(f"Proof already stored for SBOM hash {sbom_hash}")
        return jsonify({
            "ipfs_cid": existing.ipfs_cid,
            "sbom_hash": sbom_hash
        }), 200
    
    if not ipfs_client.is_connected():
        cid = f"QmMock{sbom_hash[:10]}"
        logger.warning(f"IPFS not connected, using mock CID: {cid}")
    else:
        try:
            cid = ipfs_client.add_bytes(proof_bytes)
            logger.info(f"Stored proof on IPFS with CID: {cid}")
        except Exception as e:
            logger.error(f"Failed to store on IPFS: {e}")
            return jsonify({"error": f"Failed to store on IPFS: {e}"}), 500
    
    mapping = ProofMapping(sbom_hash=sbom_hash, ipfs_cid=cid)
    try:
        db.session.add(mapping)
        db.session.commit()
        logger.info(f"Stored mapping: {sbom_hash} -> {cid}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to store mapping in database: {e}")
        return jsonify({"error": "Failed to store mapping"}), 500
    
    return jsonify({
        "ipfs_cid": cid,
        "sbom_hash": sbom_hash
    }), 201

@bp.route("/retrieve/<sbom_hash>", methods=["GET"])
def retrieve(sbom_hash):
    try:
        normalized_hash = normalize_sbom_hash(sbom_hash)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    mapping = ProofMapping.query.filter_by(sbom_hash=normalized_hash).first()
    if not mapping:
        logger.warning(f"SBOM hash not found: {normalized_hash}")
        return jsonify({"error": "SBOM hash not found"}), 404
    
    if not ipfs_client.is_connected():
        return jsonify({"error": "IPFS not connected"}), 503
    
    try:
        proof_bytes = ipfs_client.cat(mapping.ipfs_cid)
        proof_base64 = base64.b64encode(proof_bytes).decode("utf-8")
        
        logger.info(f"Retrieved proof for SBOM hash: {normalized_hash}")
        return jsonify({
            "proof": proof_base64,
            "ipfs_cid": mapping.ipfs_cid,
            "sbom_hash": normalized_hash
        }), 200
    except Exception as e:
        logger.error(f"Failed to retrieve from IPFS: {e}")
        return jsonify({"error": f"Failed to retrieve from IPFS: {e}"}), 500

@bp.route("/list", methods=["GET"])
def list_mappings():
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)
    
    if limit > 1000:
        limit = 1000
    if limit < 1:
        limit = 1
    
    mappings = ProofMapping.query.order_by(ProofMapping.created_at.desc()).limit(limit).offset(offset).all()
    total = ProofMapping.query.count()
    
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "mappings": [m.to_dict() for m in mappings]
    }), 200

