import React, { useEffect, useState } from 'react';
import {
  Page,
  Header,
  Content,
  ContentHeader,
  SupportButton,
  Progress,
  InfoCard,
  StructuredMetadataTable,
} from '@backstage/core-components';
import { Grid, Typography, Chip } from '@material-ui/core';
import {
  Table,
  TableColumn,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@backstage/core-components';
import { makeStyles } from '@material-ui/core/styles';
import CheckCircleIcon from '@material-ui/icons/CheckCircle';
import ErrorIcon from '@material-ui/icons/Error';

const useStyles = makeStyles(theme => ({
  validChip: {
    backgroundColor: theme.palette.success.main,
    color: theme.palette.success.contrastText,
  },
  invalidChip: {
    backgroundColor: theme.palette.error.main,
    color: theme.palette.error.contrastText,
  },
  metricCard: {
    height: '100%',
  },
  metricValue: {
    fontSize: '3rem',
    fontWeight: 'bold',
    marginTop: theme.spacing(2),
  },
}));

interface SBOMEntry {
  hash: string;
  softwareDigest: string;
  identifier: string;
  imageId: string;
  ipfsCid: string;
  isValid: boolean;
  bannedListHash: string;
  timestamp: number;
  submitter: string;
}

interface ServiceHealth {
  status: string;
  url: string;
  error?: string;
}

export const SbomPage = () => {
  const classes = useStyles();
  const [sboms, setSboms] = useState<SBOMEntry[]>([]);
  const [serviceHealth, setServiceHealth] = useState<Record<string, ServiceHealth>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        
        // Fetch SBOMs
        const sbomResponse = await fetch('/api/sbom/sboms');
        if (!sbomResponse.ok) {
          throw new Error('Failed to fetch SBOMs');
        }
        const sbomData = await sbomResponse.json();
        setSboms(sbomData.sboms || []);

        // Fetch service health
        const healthResponse = await fetch('/api/sbom/services/health');
        if (healthResponse.ok) {
          const healthData = await healthResponse.json();
          setServiceHealth(healthData);
        }

        setLoading(false);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <Progress />;
  }

  if (error) {
    return (
      <Page themeId="tool">
        <Header title="SBOM Management" />
        <Content>
          <InfoCard title="Error">
            <Typography color="error">{error}</Typography>
          </InfoCard>
        </Content>
      </Page>
    );
  }

  const validSboms = sboms.filter(s => s.isValid).length;
  const invalidSboms = sboms.filter(s => !s.isValid).length;
  const healthyServices = Object.values(serviceHealth).filter(s => s.status === 'healthy').length;
  const totalServices = Object.keys(serviceHealth).length;

  const columns: TableColumn[] = [
    { title: 'Identifier', field: 'identifier' },
    { title: 'Validation', field: 'isValid' },
    { title: 'Timestamp', field: 'timestamp' },
    { title: 'IPFS CID', field: 'ipfsCid' },
    { title: 'SBOM Hash', field: 'hash' },
  ];

  return (
    <Page themeId="tool">
      <Header title="SBOM Management" subtitle="Zero-Knowledge Proof SBOM Verification System">
        <SupportButton>Manage and verify SBOMs with ZKP</SupportButton>
      </Header>
      <Content>
        <ContentHeader title="Dashboard">
          <Typography>Real-time overview of SBOM validation status and service health</Typography>
        </ContentHeader>

        {/* Metrics Grid */}
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <InfoCard title="Total SBOMs" className={classes.metricCard}>
              <Typography className={classes.metricValue}>{sboms.length}</Typography>
            </InfoCard>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <InfoCard title="Valid SBOMs" className={classes.metricCard}>
              <Typography className={classes.metricValue} style={{ color: '#4caf50' }}>
                {validSboms}
              </Typography>
            </InfoCard>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <InfoCard title="Invalid SBOMs" className={classes.metricCard}>
              <Typography className={classes.metricValue} style={{ color: '#f44336' }}>
                {invalidSboms}
              </Typography>
            </InfoCard>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <InfoCard title="Service Health" className={classes.metricCard}>
              <Typography className={classes.metricValue}>
                {healthyServices}/{totalServices}
              </Typography>
            </InfoCard>
          </Grid>
        </Grid>

        {/* Service Health Status */}
        <Grid container spacing={3} style={{ marginTop: '24px' }}>
          <Grid item xs={12}>
            <InfoCard title="Service Status">
              <Grid container spacing={2}>
                {Object.entries(serviceHealth).map(([name, health]) => (
                  <Grid item xs={12} sm={6} md={3} key={name}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {health.status === 'healthy' ? (
                        <CheckCircleIcon style={{ color: '#4caf50' }} />
                      ) : (
                        <ErrorIcon style={{ color: '#f44336' }} />
                      )}
                      <div>
                        <Typography variant="subtitle1" style={{ textTransform: 'capitalize' }}>
                          {name}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          {health.status}
                        </Typography>
                      </div>
                    </div>
                  </Grid>
                ))}
              </Grid>
            </InfoCard>
          </Grid>
        </Grid>

        {/* SBOM Table */}
        <Grid container spacing={3} style={{ marginTop: '24px' }}>
          <Grid item xs={12}>
            <InfoCard title="SBOM Registry">
              <Table
                options={{
                  paging: true,
                  pageSize: 10,
                  search: true,
                  sorting: true,
                }}
                data={sboms}
                columns={columns}
                renderRow={(sbom: SBOMEntry) => (
                  <TableRow key={sbom.hash}>
                    <TableCell>{sbom.identifier}</TableCell>
                    <TableCell>
                      <Chip
                        icon={sbom.isValid ? <CheckCircleIcon /> : <ErrorIcon />}
                        label={sbom.isValid ? 'Valid' : 'Invalid'}
                        className={sbom.isValid ? classes.validChip : classes.invalidChip}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      {new Date(sbom.timestamp * 1000).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" style={{ fontFamily: 'monospace' }}>
                        {sbom.ipfsCid.substring(0, 12)}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" style={{ fontFamily: 'monospace' }}>
                        {sbom.hash.substring(0, 16)}...
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              />
            </InfoCard>
          </Grid>
        </Grid>
      </Content>
    </Page>
  );
};
