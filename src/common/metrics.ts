import type { MetricsService } from '@darmawanweb/ais-its-nest/metrics';

/**
 * prom-client metric types as returned by the kit's `MetricsService`
 * (prom-client is a dependency of the kit, not of this service).
 */
export type CounterMetric = ReturnType<MetricsService['counter']>;
