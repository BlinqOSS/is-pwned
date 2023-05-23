import { GlobalWithFetchMock } from 'jest-fetch-mock';

type Global = GlobalWithFetchMock & {
  window: any;
};

const customGlobal: Global = global as unknown as Global;
customGlobal.fetch = require('jest-fetch-mock');
customGlobal.fetchMock = customGlobal.fetch;
customGlobal.window = {};
