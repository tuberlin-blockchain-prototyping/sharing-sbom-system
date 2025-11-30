import base64
import logging
from flask import Blueprint, request, jsonify
from models import db, ProofMapping
from ipfs_client import ipfs_client

logger = logging.getLogger(__name__)

bp = Blueprint("api", __name__)


@bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "ipfs_connected": ipfs_client.is_connected()})


@bp.route("/store", methods=["POST"])
def store():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    proof_base64 = data.get("proof")
    composite_hash = data.get("composite_hash")

    if not proof_base64:
        return jsonify({"error": "Missing 'proof' field"}), 400
    if not composite_hash:
        return jsonify({"error": "Missing 'composite_hash' field"}), 400

    try:
        proof_bytes = base64.b64decode(proof_base64)
    except Exception as e:
        logger.warning(f"Invalid base64 proof: {e}")
        return jsonify({"error": f"Invalid base64 proof: {e}"}), 400

    if not ipfs_client.is_connected():
        logger.error("IPFS not connected - cannot store proof")
        return (
            jsonify({"error": "IPFS not connected. IPFS is required to store proofs."}),
            503,
        )

    existing = ProofMapping.query.filter_by(composite_hash=composite_hash).first()
    if existing:
        logger.info(f"Proof already stored for composite hash {composite_hash}")
        return (
            jsonify({"ipfs_cid": existing.ipfs_cid, "composite_hash": composite_hash}),
            200,
        )

    try:
        cid = ipfs_client.add_bytes(proof_bytes)
        logger.info(f"Stored proof on IPFS with CID: {cid}")
    except Exception as e:
        logger.error(f"Failed to store on IPFS: {e}")
        return jsonify({"error": f"Failed to store on IPFS: {e}"}), 500

    mapping = ProofMapping(composite_hash=composite_hash, ipfs_cid=cid)
    try:
        db.session.add(mapping)
        db.session.commit()
        logger.info(f"Stored mapping: {composite_hash} -> {cid}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to store mapping in database: {e}")
        return jsonify({"error": "Failed to store mapping"}), 500

    return jsonify({"ipfs_cid": cid, "composite_hash": composite_hash}), 201


@bp.route("/retrieve/<composite_hash>", methods=["GET"])
def retrieve(composite_hash):
    if not ipfs_client.is_connected():
        logger.error("IPFS not connected - cannot retrieve proof")
        return (
            jsonify(
                {"error": "IPFS not connected. IPFS is required to retrieve proofs."}
            ),
            503,
        )

    mapping = ProofMapping.query.filter_by(composite_hash=composite_hash).first()
    if not mapping:
        logger.warning(f"Composite hash not found: {composite_hash}")
        return jsonify({"error": "Composite hash not found"}), 404

    try:
        proof_bytes = ipfs_client.cat(mapping.ipfs_cid)
        proof_base64 = base64.b64encode(proof_bytes).decode("utf-8")

        logger.info(f"Retrieved proof from IPFS for composite hash: {composite_hash}")
        return (
            jsonify(
                {
                    "proof": proof_base64,
                    "ipfs_cid": mapping.ipfs_cid,
                    "composite_hash": composite_hash,
                }
            ),
            200,
        )
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

    mappings = (
        ProofMapping.query.order_by(ProofMapping.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    total = ProofMapping.query.count()

    return (
        jsonify(
            {
                "total": total,
                "limit": limit,
                "offset": offset,
                "mappings": [m.to_dict() for m in mappings],
            }
        ),
        200,
    )
