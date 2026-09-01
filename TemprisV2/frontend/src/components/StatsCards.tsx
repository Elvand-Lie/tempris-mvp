// frontend/src/components/StatsCards.tsx
import React from 'react';
import { AssetStats, CollectorStats } from '../types';

interface StatsCardsProps {
  type?: 'assets' | 'collectors';
  assetStats?: AssetStats | null;
  collectorStats?: CollectorStats | null;
  loading: boolean;
}

export const StatsCards: React.FC<StatsCardsProps> = ({
  type = 'assets',
  assetStats,
  collectorStats,
  loading,
}) => {
  if (type === 'collectors') {
    const collectorCards = [
      {
        id: 'stat-total-collectors',
        label: 'Total Collectors',
        value: collectorStats ? collectorStats.total_collectors : loading ? '...' : 0,
        hint: 'Registered tenant collectors',
      },
      {
        id: 'stat-connected-collectors',
        label: 'Connected (Live WSS)',
        value: collectorStats ? collectorStats.connected_collectors : loading ? '...' : 0,
        hint: 'Active authenticated sockets',
      },
      {
        id: 'stat-awaiting-enrollment',
        label: 'Awaiting Enrollment',
        value: collectorStats ? collectorStats.awaiting_enrollment : loading ? '...' : 0,
        hint: 'Pending client key submission',
      },
      {
        id: 'stat-paused-quarantined',
        label: 'Paused / Quarantined',
        value: collectorStats ? collectorStats.paused_or_quarantined : loading ? '...' : 0,
        hint: 'Operator suspended or rate-limited',
      },
    ];

    return (
      <section className="stats-grid" aria-label="Collector Statistics">
        {collectorCards.map((card) => (
          <div key={card.id} id={card.id} className="stat-card">
            <div className="stat-header">
              <span className="stat-label">{card.label}</span>
            </div>
            <div className="stat-value">{card.value}</div>
            <div className="stat-hint">{card.hint}</div>
          </div>
        ))}
      </section>
    );
  }

  const assetCards = [
    {
      id: 'stat-total-assets',
      label: 'Total Assets',
      value: assetStats ? assetStats.total_assets : loading ? '...' : 0,
      hint: 'Active tenant assets',
    },
    {
      id: 'stat-reachable-by-scout',
      label: 'Reachable by Scout',
      value: assetStats ? assetStats.reachable_by_scout : loading ? '...' : 0,
      hint: 'Verified Internet targets',
    },
    {
      id: 'stat-authorized-to-scan',
      label: 'Authorized to Scan',
      value: assetStats ? assetStats.authorized_to_scan : loading ? '...' : 0,
      hint: 'Approved unexpired target tuples',
    },
    {
      id: 'stat-pending-authorization',
      label: 'Pending Authorization',
      value: assetStats ? assetStats.pending_authorization : loading ? '...' : 0,
      hint: 'Awaiting admin approval',
    },
    {
      id: 'stat-no-scanner-available',
      label: 'No Scanner Available',
      value: assetStats ? assetStats.no_scanner_available : loading ? '...' : 0,
      hint: 'Internal scope assets',
    },
  ];

  return (
    <section className="stats-grid" aria-label="Asset Statistics">
      {assetCards.map((card) => (
        <div key={card.id} id={card.id} className="stat-card">
          <div className="stat-header">
            <span className="stat-label">{card.label}</span>
          </div>
          <div className="stat-value">{card.value}</div>
          <div className="stat-hint">{card.hint}</div>
        </div>
      ))}
    </section>
  );
};
