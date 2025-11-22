import {
  createPlugin,
  createRoutableExtension,
} from '@backstage/core-plugin-api';

import { rootRouteRef } from './routes';

export const sbomPlugin = createPlugin({
  id: 'sbom',
  routes: {
    root: rootRouteRef,
  },
});

export const SbomPage = sbomPlugin.provide(
  createRoutableExtension({
    name: 'SbomPage',
    component: () =>
      import('./components/SbomPage').then(m => m.SbomPage),
    mountPoint: rootRouteRef,
  }),
);
