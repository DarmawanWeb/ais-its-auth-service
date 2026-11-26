import { isIsoDateTime } from '@darmawanweb/ais-its-contracts/api';
import {
  buildMessage,
  ValidateBy,
  type ValidationOptions,
} from 'class-validator';

/**
 * Validates a wire timestamp (spec §2: ISO-8601 UTC strings on the wire):
 * a calendar date and time with seconds and a `Z` suffix, e.g.
 * `2027-01-01T00:00:00Z` (contracts `isIsoDateTime`, the rule of the kit's
 * `from` / `to`). Everything `Date` cannot read, or reads differently from
 * what was meant, fails: week dates (`2027-W05`), ordinal dates
 * (`2027-123`), the basic format (`20270101`), signed years, and times
 * without a zone (which `Date` would read in the server's time zone).
 */
export function IsUtcDateTime(options?: ValidationOptions): PropertyDecorator {
  return ValidateBy(
    {
      name: 'isUtcDateTime',
      validator: {
        validate: (value: unknown) => isIsoDateTime(value),
        defaultMessage: buildMessage(
          (each) =>
            `${each}$property must be an ISO-8601 UTC timestamp such as 2027-01-01T00:00:00Z`,
          options,
        ),
      },
    },
    options,
  );
}
