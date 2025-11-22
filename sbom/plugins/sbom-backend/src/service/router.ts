import { LoggerService } from '@backstage/backend-plugin-api';
import { Config } from '@backstage/config';
import express from 'express';
import Router from 'express-promise-router';
import fetch from 'node-fetch';
import { ethers } from 'ethers';

export interface RouterOptions {
  logger: LoggerService;
  config: Config;
}

// Smart Contract ABI
const SBOM_REGISTRY_ABI = [
  'function getSBOM(bytes32 hash) external view returns (tuple(bytes32 hash, bytes32 softwareDigest, string identifier, bytes32 imageId, string ipfsCid, bool isValid, bytes32 bannedListHash, uint256 timestamp, address submitter))',
  'function exists(bytes32 hash) external view returns (bool)',
  'function listHashes() external view returns (bytes32[])',
];

const CONTRACT_ADDRESS = '0x5FbDB2315678afecb367f032d93F642f64180aa3';

export async function createRouter(
  options: RouterOptions,
): Promise<express.Router> {
  const { logger } = options;

  const router = Router();
  router.use(express.json());

  // Health check
  router.get('/health', (_req, res) => {
    logger.info('Health check called');
    res.json({ status: 'ok' });
  });

  // Get all SBOMs from blockchain
  router.get('/sboms', async (_req, res) => {
    try {
      const blockchainUrl = process.env.BLOCKCHAIN_RPC_URL || 'http://hardhat-node.blockchain.svc.cluster.local:8545';
      const provider = new ethers.JsonRpcProvider(blockchainUrl);
      const contract = new ethers.Contract(CONTRACT_ADDRESS, SBOM_REGISTRY_ABI, provider);

      const hashes = await contract.listHashes();
      const sboms = [];

      for (const hash of hashes) {
        try {
          const entry = await contract.getSBOM(hash);
          sboms.push({
            hash: entry.hash,
            softwareDigest: entry.softwareDigest,
            identifier: entry.identifier,
            imageId: entry.imageId,
            ipfsCid: entry.ipfsCid,
            isValid: entry.isValid,
            bannedListHash: entry.bannedListHash,
            timestamp: Number(entry.timestamp),
            submitter: entry.submitter,
          });
        } catch (err) {
          logger.warn(`Failed to get SBOM for hash ${hash}: ${err}`);
        }
      }

      res.json({ sboms, total: sboms.length });
    } catch (error) {
      logger.error(`Failed to fetch SBOMs from blockchain: ${error}`);
      res.status(500).json({ error: 'Failed to fetch SBOMs' });
    }
  });

  // Get SBOM by hash
  router.get('/sboms/:hash', async (req, res) => {
    try {
      const { hash } = req.params;
      const blockchainUrl = process.env.BLOCKCHAIN_RPC_URL || 'http://hardhat-node.blockchain.svc.cluster.local:8545';
      const provider = new ethers.JsonRpcProvider(blockchainUrl);
      const contract = new ethers.Contract(CONTRACT_ADDRESS, SBOM_REGISTRY_ABI, provider);

      const hashBytes32 = hash.startsWith('0x') ? hash : `0x${hash}`;
      const exists = await contract.exists(hashBytes32);

      if (!exists) {
        res.status(404).json({ error: 'SBOM not found' });
        return;
      }

      const entry = await contract.getSBOM(hashBytes32);
      res.json({
        hash: entry.hash,
        softwareDigest: entry.softwareDigest,
        identifier: entry.identifier,
        imageId: entry.imageId,
        ipfsCid: entry.ipfsCid,
        isValid: entry.isValid,
        bannedListHash: entry.bannedListHash,
        timestamp: Number(entry.timestamp),
        submitter: entry.submitter,
      });
    } catch (error) {
      logger.error(`Failed to fetch SBOM: ${error}`);
      res.status(500).json({ error: 'Failed to fetch SBOM' });
    }
  });

  // Verify proof
  router.post('/verify', async (req, res) => {
    try {
      const { proof } = req.body;

      if (!proof) {
        res.status(400).json({ error: 'Missing proof field' });
        return;
      }

      const verifierUrl = process.env.VERIFIER_SERVICE_URL || 'http://verifier-service.sharing-sbom-system.svc.cluster.local';
      const response = await fetch(`${verifierUrl}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        res.status(response.status).json(errorData);
        return;
      }

      const result = await response.json();
      res.json(result);
    } catch (error) {
      logger.error(`Failed to verify proof: ${error}`);
      res.status(500).json({ error: 'Failed to verify proof' });
    }
  });

  // Get proof from IPFS
  router.get('/proof/:sbomHash', async (req, res) => {
    try {
      const { sbomHash } = req.params;
      const ipfsUrl = process.env.IPFS_SERVICE_URL || 'http://ipfs-service.sharing-sbom-system.svc.cluster.local';
      
      const response = await fetch(`${ipfsUrl}/retrieve/${sbomHash}`);

      if (!response.ok) {
        const errorData = await response.json();
        res.status(response.status).json(errorData);
        return;
      }

      const result = await response.json();
      res.json(result);
    } catch (error) {
      logger.error(`Failed to retrieve proof from IPFS: ${error}`);
      res.status(500).json({ error: 'Failed to retrieve proof' });
    }
  });

  // Service health checks
  router.get('/services/health', async (_req, res) => {
    const services = {
      proving: process.env.PROVING_SERVICE_URL || 'http://proving-service.sharing-sbom-system.svc.cluster.local',
      verifier: process.env.VERIFIER_SERVICE_URL || 'http://verifier-service.sharing-sbom-system.svc.cluster.local',
      ipfs: process.env.IPFS_SERVICE_URL || 'http://ipfs-service.sharing-sbom-system.svc.cluster.local',
      blockchain: process.env.BLOCKCHAIN_RPC_URL || 'http://hardhat-node.blockchain.svc.cluster.local:8545',
    };

    const healthStatuses: Record<string, any> = {};

    for (const [name, url] of Object.entries(services)) {
      try {
        const healthUrl = name === 'blockchain' ? url : `${url}/health`;
        const response = await fetch(healthUrl, { timeout: 5000 } as any);
        healthStatuses[name] = {
          status: response.ok ? 'healthy' : 'unhealthy',
          url,
        };
      } catch (error) {
        healthStatuses[name] = {
          status: 'unreachable',
          url,
          error: String(error),
        };
      }
    }

    res.json(healthStatuses);
  });

  return router;
}
