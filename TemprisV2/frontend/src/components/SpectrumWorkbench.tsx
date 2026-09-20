import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { SpectrumQueueItem } from '../types';
import { SpectrumQueue } from './SpectrumQueue';
import { SpectrumExposureDetail } from './SpectrumExposureDetail';

/**
 * SPECTRUM workbench shell: the queue over current confirmed exposures plus
 * the per-exposure workbench. Queue state lives here so workflow mutations in
 * the detail can refresh the row without losing the analyst's place; the
 * selected row rides along as display context for the detail header.
 */
export const SpectrumWorkbench: React.FC = () => {
  const [items, setItems] = useState<SpectrumQueueItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<SpectrumQueueItem | null>(null);
  const detailRef = useRef<HTMLDivElement>(null);

  const loadQueue = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.spectrum.getQueue();
      setItems(response.items);
      setTotal(response.total);
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
    if (!selected) return;
    const anchor = detailRef.current;
    if (anchor && typeof anchor.scrollIntoView === 'function') {
      anchor.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [selected]);

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
        total={total}
        loading={loading}
        error={error}
        selectedId={selected?.exposure_id ?? null}
        onSelect={setSelected}
        onRefresh={loadQueue}
      />

      <div ref={detailRef}>
        {selected && (
          <SpectrumExposureDetail
            exposureId={selected.exposure_id}
            context={selected}
            onChanged={loadQueue}
            onBack={() => setSelected(null)}
          />
        )}
        {!selected && !loading && !error && items.length > 0 && (
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
