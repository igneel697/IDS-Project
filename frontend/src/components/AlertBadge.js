import React from 'react';

/**
 * Coloured severity badge component
 */
function AlertBadge({ severity }) {
  const cls = severity ? `badge badge-${severity.toLowerCase()}` : 'badge';
  return <span className={cls}>{severity}</span>;
}

export default AlertBadge;
