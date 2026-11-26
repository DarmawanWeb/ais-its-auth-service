import {
  type EmailRequestedV1,
  EVENT_TYPES,
} from '@darmawanweb/ais-its-contracts/events';
import {
  type Counter,
  MetricsService,
} from '@darmawanweb/ais-its-nest/metrics';
import { EventPublisher } from '@darmawanweb/ais-its-nest/nats';
import { Injectable, Logger } from '@nestjs/common';

import { failureMessage } from '../../common/background-work.js';

/**
 * Requests transactional e-mails from the notification service by
 * publishing `notify.email.requested.v1` to the `NOTIFY` work queue
 * (spec §7.3; this service ensures the stream as a producer). The payload
 * carries one-time links: it is never logged.
 */
@Injectable()
export class EmailRequester {
  private readonly logger = new Logger('EmailRequester');
  private readonly requests: Counter<'template' | 'outcome'>;

  constructor(
    private readonly publisher: EventPublisher,
    metrics: MetricsService,
  ) {
    this.requests = metrics.counter({
      name: 'auth_emails_requested_total',
      help: 'Transactional e-mails requested from the notification service, by template and outcome.',
      labelNames: ['template', 'outcome'],
    });
  }

  /**
   * Publishes the request; resolves `false` (logged and counted) when NATS
   * does not acknowledge it, so callers decide whether that is fatal.
   */
  async request(email: EmailRequestedV1): Promise<boolean> {
    try {
      await this.publisher.publishEvent(
        EVENT_TYPES.NOTIFY_EMAIL_REQUESTED,
        email,
      );
      this.requests.inc({ template: email.template, outcome: 'published' });
      return true;
    } catch (error) {
      this.requests.inc({ template: email.template, outcome: 'failed' });
      this.logger.error(
        `Requesting the ${email.template} e-mail failed: ${failureMessage(error)}`,
      );
      return false;
    }
  }
}
