import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { SpectrumQueueItem } from '../types';
import { SpectrumQueue } from './SpectrumQueue';
import { SpectrumExposureDetail } from './SpectrumExposureDetail';

/**
 * SPECTRUM workbench shell: the queue over current confirmed exposures plus
 * the per-exposure workbench. Queue state lives here so workflow mutations in
 * the detail can refresh the row without losing the analyst's place.
 */
export const SpectrumWorkbench: React.FC = () => {
  const [items, setItems] = useState<SpectrumQueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const detailRef = useRef<HTMLDivElement>(null);

  const loadQueue = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await api.spectrum.getQueue());
    } catch (cause: any) {
      setError(cause.message || 'The exposure queue could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadQueue();
  }, [loadQueue]);

  useEffect(() => {
    if (!selectedId) return;
    const anchor = detailRef.current;
    if (anchor && typeof anchor.scrollIntoView === 'function') {
      anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [selectedId]);

  return (
    <section className="spectrum-workbench" aria-labelledby="spectrum-title">
      <div className="scout-hero">
        <div>
          <p className="scout-kicker">SPECTRUM</p>
          <h1 id="spectrum-title">Confirmed-exposure workbench</h1>
          <p>
            Read-through scores and analyst ownership over current confirmed exposures. Scores are recomputed by the
            exposure domain on every read — SPECTRUM never stores them.
          </p>
        </div>
        <button className="btn btn-secondary" type="button" onClick={loadQueue} disabled={loading}>
          Refresh live data
        </button>
      </div>

      <SpectrumQueue
        items={items}
        loading={loading}
        error={error}
        selectedId={selectedId}
        onSelect={setSelectedId}
        onRefresh={loadQueue}
      />

      <div ref={detailRef}>
        {selectedId && (
          <SpectrumExposureDetail exposureId={selectedId} onChanged={loadQueue} onBack={() => setSelectedId(null)} />
        )}
        {!selectedId && !loading && !error && items.length > 0 && (
          <div className="scout-panel">
            <p className="scout-empty" role="status">
              Select an exposure to open the workbench.
            </p>
          </div>
        )}
      </div>
    </section>
  );
};
