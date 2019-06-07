# is-pwned

##### Check if passwords are PWNED before they're used

## Purpose

[Credential stuffing](https://www.owasp.org/index.php/Credential_stuffing) is a very real threat to web application security and it's important that businesses are doing their best to protect their users from passwords that been been seen in known breaches.

This library is designed to be hooked into your _login_ or _change password_ forms to ensure that users aren't using or setting passwords seen in known breaches. This is achieved by sending the first five characters of a SHA-1 copy of the user's password to [Have I Been Pwned](https://haveibeenpwned.com/API/v2)'s API and matching it against the result set that is returned.

TL;DR: This adds breached password detection to input fields of your choice and has a configurable timeout so it doesn't block your login.

#### Note: This library is intended for browser use only. In future versions it might support Node but the intent is to keep the library free from dependencies.

## Installation

Install the `is-pwned` package using `npm` or `yarn`.

```bash
npm i -S is-pwned
```

```bash
yarn add is-pwned
```

### Import the Module & Configure

Import the module and instantiate the class. TypeScript types are available.

```typescript
import IsPwned from 'is-pwned';

const pw = new IsPwned(config);
```

## Methods

### Check Password (`pw.check()`)

pw.check returns a promise that resolves `true` or reject with an `Error`. See _Error Handling_ below.

```typescript
const pw = new IsPwned(config);

pw.check('password'); // Promise<true>
```

### Hash Password (`pw.hashPassword()`)

Exposes the internal password hashing method.

```typescript
const pw = new IsPwned(config);

pw.hashPassword('password'); // '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'
```

## Error Handling

Methods in the `is-pwned` library use custom errors so you can better handle responses.

```typescript
try {
  await pw.check('password');
} catch (e) {
  switch (e.name) {
    case 'UnexpectedHttpResponseError':
    // A response other than 200 was received from HIBP
    case 'TimedOutError':
    // The timeout was reached
    case 'InvalidPasswordError':
    // The password is either not a string or is empty
    case 'BreachedError':
      // The password has been breached
      // You can use e.count on this error type
      console.log(`Password has been breached ${e.count} times.`);
  }
}
```

## Configuration

IsPwned can be configured accordingly:

| Option             | Type                 | Default                                 | Purpose                                         |
| :----------------- | :------------------- | :-------------------------------------- | :---------------------------------------------- |
| `endpoint`         | `string` (optional)  | `https://api.pwnedpasswords.com/range/` | Substitute the HIBP endpoit for your own.       |
| `timeout`          | `number` (optional)  | `5000`                                  | Timeout on the check.                           |
| `userAgent`        | `string` (optional)  | `is-pwned-js`                           | Change the UserAgent to represent your service. |
| `resolveOnTimeout` | `boolean` (optional) | `false`                                 | Resolve instead of erroring on timeout.         |

### `endpoint`

In some environments a business may choose to either proxy or host their own HIBP endpoint. The script will pass the first five characters of the SHA-1'd password to the last url part — for example: `https://api.pwnedpasswords.com/range/{hash}`

### `timeout`

To ensure that the user experience isn't adversely affected by the additional HTTP request it is recommended to set a timeout. The default timeout is `5000` milliseconds, but you may want to change this depending on your situation.

### `userAgent`

The [HIBP API Acceptable Use Policy](https://haveibeenpwned.com/API/v2#AcceptableUse) requires that user agent "accurately describe the nature of the API consumer such that it can be clearly identified in the request". It is recommended that you change this, however it will default to `is-pwned-js`.

Please also refer to the licensing requirements for using the [Passwords API](https://haveibeenpwned.com/API/v2#License). Accreditation isn't required but it is welcomed by HIBP.

### `resolveOnTimeout`

Setting this to `true` will resolve the `check` method promise if it times out which can assist in some programming situations. This is not recommended as you should try and handle this in your codebase.
