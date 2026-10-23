// Entry point for the Raylane Web UI.
//
// T002 scope: inert build scaffold. It renders a static placeholder and makes
// no network request, opens no socket and reads no configuration.
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import './styles.css';

const container = document.getElementById('root');

if (!container) {
  // A missing mount point is a build defect, not a runtime condition to
  // recover from silently.
  throw new Error('Raylane: mount point #root is missing');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
