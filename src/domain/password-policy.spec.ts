import { describe, expect, it } from 'vitest';

import {
  checkPasswordPolicy,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  passwordViolationMessage,
} from './password-policy.js';

describe('checkPasswordPolicy (spec §13.1: ≥ 10 characters with letters and digits)', () => {
  it('accepts passwords with at least 10 characters, a letter and a digit', () => {
    expect(checkPasswordPolicy('CorrectHorse42')).toEqual([]);
    expect(checkPasswordPolicy('a1a1a1a1a1')).toEqual([]);
    expect(checkPasswordPolicy('ChangeMe123!')).toEqual([]);
  });

  it('counts code points and accepts letters and digits of any script', () => {
    expect(checkPasswordPolicy('kapal laut 7')).toEqual([]);
    expect(checkPasswordPolicy('пароль١٢٣٤٥')).toEqual([]); // Cyrillic letters, Arabic-Indic digits
    expect(checkPasswordPolicy('🚢🚢🚢🚢🚢🚢🚢🚢a1')).toEqual([]); // 10 code points, 18 UTF-16 units
    expect(checkPasswordPolicy('🚢🚢🚢🚢🚢🚢🚢a1')).toEqual(['too_short']);
  });

  it('reports every violated rule in a stable order', () => {
    expect(checkPasswordPolicy('')).toEqual(['too_short', 'missing_letter', 'missing_digit']);
    expect(checkPasswordPolicy('short1')).toEqual(['too_short']);
    expect(checkPasswordPolicy('onlyletters')).toEqual(['missing_digit']);
    expect(checkPasswordPolicy('1234567890')).toEqual(['missing_letter']);
    expect(checkPasswordPolicy(`a1${'x'.repeat(PASSWORD_MAX_LENGTH)}`)).toEqual(['too_long']);
  });

  it('has the documented bounds and messages', () => {
    expect(PASSWORD_MIN_LENGTH).toBe(10);
    expect(checkPasswordPolicy(`a1${'x'.repeat(PASSWORD_MAX_LENGTH - 2)}`)).toEqual([]);
    expect(passwordViolationMessage('too_short')).toBe('must be at least 10 characters long');
    expect(passwordViolationMessage('missing_digit')).toBe('must contain at least one digit');
  });
});
