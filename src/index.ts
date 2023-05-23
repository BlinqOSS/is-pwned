interface IsPwnedConfig {
  endpoint?: string;
  timeout?: number;
  userAgent?: string;
  resolveOnTimeout?: boolean;
}

export class UnexpectedHttpResponseError extends Error {
  constructor(responseText: string) {
    super(`IsPwned received an unexpected HTTP response: ${responseText}`);
    this.name = 'UnexpectedHttpResponseError';
  }
}

export class TimedOutError extends Error {
  constructor() {
    super('IsPwned timed out while making request.');
    this.name = 'TimedOutError';
  }
}

export class InvalidPasswordError extends Error {
  constructor() {
    super('IsPwned received an invalid or empty password.');
    this.name = 'InvalidPasswordError';
  }
}

export class BreachedError extends Error {
  count: number;
  constructor(count: number) {
    super('This password has been detected in a known breach.');
    this.name = 'BreachedError';
    this.count = count;
  }
}

const rotateLeft = (n: number, s: number) => (n << s) | (n >>> (32 - s));

const cvtHex = (v: number) => {
  let result = '';

  for (let i = 7; i >= 0; i--) {
    result += ((v >>> (i * 4)) & 0x0f).toString(16);
  }

  return result;
};

const utf8Encode = (str: string) => {
  let result = '';
  str = str.replace(/\r\n/g, '\n');

  for (let i = 0; i < str.length; i++) {
    let char = str.charCodeAt(i);

    if (char < 128) {
      result += String.fromCharCode(char);
    } else if (char > 127 && char < 2048) {
      result += String.fromCharCode((char >> 6) | 192);
      result += String.fromCharCode((char & 63) | 128);
    } else {
      result += String.fromCharCode((char >> 12) | 224);
      result += String.fromCharCode(((char >> 6) & 63) | 128);
      result += String.fromCharCode((char & 63) | 128);
    }
  }
  return result;
};

const sha1 = (input: string) => {
  const W = new Array(80);

  let H0 = 0x67452301;
  let H1 = 0xefcdab89;
  let H2 = 0x98badcfe;
  let H3 = 0x10325476;
  let H4 = 0xc3d2e1f0;

  let str = utf8Encode(input);

  const wordArray = [];

  for (let i = 0; i < str.length - 3; i += 4) {
    wordArray.push(
      (str.charCodeAt(i) << 24) |
        (str.charCodeAt(i + 1) << 16) |
        (str.charCodeAt(i + 2) << 8) |
        str.charCodeAt(i + 3)
    );
  }

  wordArray.push(
    (() => {
      switch (str.length % 4) {
        case 0:
          return 0x080000000;
        case 1:
          return (str.charCodeAt(str.length - 1) << 24) | 0x0800000;
        case 2:
          return (
            (str.charCodeAt(str.length - 2) << 24) |
            (str.charCodeAt(str.length - 1) << 16) |
            0x08000
          );
        case 3:
          return (
            (str.charCodeAt(str.length - 3) << 24) |
            (str.charCodeAt(str.length - 2) << 16) |
            (str.charCodeAt(str.length - 1) << 8) |
            0x80
          );
      }
    })()
  );

  while (wordArray.length % 16 !== 14) {
    wordArray.push(0);
  }

  wordArray.push(str.length >>> 29);
  wordArray.push((str.length << 3) & 0x0ffffffff);

  let A, B, C, D, E, iii;

  for (let i = 0; i < wordArray.length; i += 16) {
    // First round
    for (let ii = 0; ii < 16; ii++) {
      W[ii] = wordArray[i + ii];
    }
    // Second Round
    for (let ii = 16; ii <= 79; ii++) {
      W[ii] = rotateLeft(W[ii - 3] ^ W[ii - 8] ^ W[ii - 14] ^ W[ii - 16], 1);
    }

    A = H0;
    B = H1;
    C = H2;
    D = H3;
    E = H4;

    // Encoding Round 1
    for (let ii = 0; ii <= 19; ii++) {
      iii =
        (rotateLeft(A, 5) + ((B & C) | (~B & D)) + E + W[ii] + 0x5a827999) &
        0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = iii;
    }

    // Encoding Round 2
    for (let ii = 20; ii <= 39; ii++) {
      iii =
        (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[ii] + 0x6ed9eba1) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = iii;
    }

    // Encoding Round 3
    for (let ii = 40; ii <= 59; ii++) {
      iii =
        (rotateLeft(A, 5) +
          ((B & C) | (B & D) | (C & D)) +
          E +
          W[ii] +
          0x8f1bbcdc) &
        0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = iii;
    }

    // Encoding Round 4
    for (let ii = 60; ii <= 79; ii++) {
      iii =
        (rotateLeft(A, 5) + (B ^ C ^ D) + E + W[ii] + 0xca62c1d6) & 0x0ffffffff;
      E = D;
      D = C;
      C = rotateLeft(B, 30);
      B = A;
      A = iii;
    }

    // Chars
    H0 = (H0 + A) & 0x0ffffffff;
    H1 = (H1 + B) & 0x0ffffffff;
    H2 = (H2 + C) & 0x0ffffffff;
    H3 = (H3 + D) & 0x0ffffffff;
    H4 = (H4 + E) & 0x0ffffffff;
  }

  return (
    cvtHex(H0) +
    cvtHex(H1) +
    cvtHex(H2) +
    cvtHex(H3) +
    cvtHex(H4)
  ).toUpperCase();
};

export default class IsPwned {
  endpoint: string;
  userAgent: string;
  timeout: number;
  resolveOnTimeout: boolean;

  constructor(config: IsPwnedConfig = {}) {
    if (typeof window === 'undefined') {
      throw new Error('IsPwned is meant for use in the browser only.');
    }

    this.endpoint = config.endpoint || 'https://api.pwnedpasswords.com/range/';
    this.userAgent = config.userAgent || 'is-pwned-js';
    this.timeout = config.timeout || 5000;
    this.resolveOnTimeout = config.resolveOnTimeout || false;
  }
  public hashPassword(password: string) {
    if (!password || typeof password !== 'string') {
      throw new InvalidPasswordError();
    }
    return sha1(password);
  }
  public async check(password: string) {
    const hashedPassword = this.hashPassword(password);

    const firstFiveOfPassword = hashedPassword.substring(0, 5);
    const remainderOfPassword = hashedPassword.substring(5);

    const breaches = (await this.makeRequest(firstFiveOfPassword))
      .split('\n')
      .filter((hs) => hs.indexOf(remainderOfPassword) > -1);

    if (breaches.length > 0) {
      throw new BreachedError(
        breaches.map((v) => parseInt(v.split(':')[1])).reduce((v, t) => v + t)
      );
    }

    return true;
  }
  private async makeRequest(firstFiveOfHash: string) {
    const abortController =
      typeof AbortController !== 'undefined'
        ? new AbortController()
        : undefined;
    const timer = setTimeout(() => {
      if (abortController) {
        abortController.abort();
      }
      if (this.resolveOnTimeout) {
        return Promise.resolve();
      }
      throw new TimedOutError();
    }, this.timeout);
    const response = await fetch(this.endpoint + firstFiveOfHash, {
      signal: abortController ? abortController.signal : undefined,
      headers: {
        'User-Agent': this.userAgent,
      },
    });
    clearTimeout(timer);

    if (response.status === 200) {
      return response.text();
    }

    throw new UnexpectedHttpResponseError(response.statusText);
  }
}
