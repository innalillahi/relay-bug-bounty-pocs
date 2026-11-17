/**
 * Jest config to run the P5 oracle PoC from this directory against a
 * relay-protocol-oracle checkout at ../../repos/relay-protocol-oracle
 * (pinned commit 55b22de). No repo mutation, no live RPC, no keys.
 * Run from this directory:
 *   ../../repos/relay-protocol-oracle/node_modules/.bin/jest --config jest.config.js --runInBand
 */
const path = require("path");
const ORACLE = path.join(__dirname, "../../repos/relay-protocol-oracle");

module.exports = {
  rootDir: path.join(__dirname, "../.."),
  verbose: true,
  testMatch: ["<rootDir>/poc/p5-oracle/*.test.ts"],
  transform: {
    "^.+\\.(t|j)s?$": [
      `${ORACLE}/node_modules/ts-jest`,
      { tsconfig: path.join(__dirname, "tsconfig.json") },
    ],
  },
  transformIgnorePatterns: [
    "node_modules/(?!(@nktkas/hyperliquid|@noble|@xrplf|@scure|ripple-address-codec|ripple-binary-codec)/)",
  ],
  moduleDirectories: [`${ORACLE}/node_modules`, "node_modules"],
};
