import { FetchMock } from 'jest-fetch-mock';
import IsPwned, {
  UnexpectedHttpResponseError,
  TimedOutError,
  InvalidPasswordError,
  BreachedError,
} from '../src/index';

describe('error exports', () => {
  test('should be instances of Error', () => {
    expect(new UnexpectedHttpResponseError('')).toBeInstanceOf(Error);
    expect(new TimedOutError()).toBeInstanceOf(Error);
    expect(new InvalidPasswordError()).toBeInstanceOf(Error);
    expect(new BreachedError(2)).toBeInstanceOf(Error);
  });
});

describe('breached error', () => {
  test('should contain count value', () => {
    try {
      throw new BreachedError(5);
    } catch (e: unknown) {
      const err = e as BreachedError;
      expect(err.name).toBe('BreachedError');
      expect(err.count).toBe(5);
    }
  });
});

describe('hashPassword', () => {
  test('should correctly sha-1 a string', () => {
    const pw = new IsPwned();
    expect(pw.hashPassword('apple pear orange grapefruit')).toEqual(
      'FB0CE8FF9619A8D2B20B0352D8AF77969B8CB25B'
    );
  });
});

describe('check', () => {
  test('should reject an empty password', () => {
    const pw = new IsPwned();
    return pw.check('').catch((e) => {
      expect(e.name).toBe('InvalidPasswordError');
    });
  });
  test('should reject non-string inputs', () => {
    const pw = new IsPwned();
    return pw.check(null as any).catch((e) => {
      expect(e.name).toBe('InvalidPasswordError');
    });
  });
  test('should error if timeout is reached', () => {
    const pw = new IsPwned({
      timeout: 0,
    });
    return pw.check('hi').catch((e) => {
      expect(e.name).toBe('TimedOutError');
    });
  });
  test('should correctly identify matching breached passwords', () => {
    const pw = new IsPwned();
    (global.fetch as FetchMock)
      .mockResponseOnce(`1D2DA4053E34E76F6576ED1DA63134B5E2A:2
    1D72CD07550416C216D8AD296BF5C0AE8E0:10
    1E2AAA439972480CEC7F16C795BBB429372:1
    1E3687A61BFCE35F69B7408158101C8E414:1
    1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345
    1F2B668E8AABEF1C59E9EC6F82E3F3CD786:1
    20597F5AC10A2F67701B4AD1D3A09F72250:3`);

    return pw.check('password').catch((e) => {
      expect(e.name).toBe('BreachedError');
      expect(e.count).toBe(12345);
    });
  });
  test('should correctly identify that no passwords are breached', () => {
    const pw = new IsPwned();
    (global.fetch as FetchMock)
      .mockResponseOnce(`1D2DA4053E34E76F6576ED1DA63134B5E2A:2
    1D72CD07550416C216D8AD296BF5C0AE8E0:10
    1E2AAA439972480CEC7F16C795BBB429372:1
    1E3687A61BFCE35F69B7408158101C8E414:1
    1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345
    1F2B668E8AABEF1C59E9EC6F82E3F3CD786:1
    20597F5AC10A2F67701B4AD1D3A09F72250:3`);

    return pw.check('blah blah blah').then((v) => {
      expect(v).toBe(true);
    });
  });
});
