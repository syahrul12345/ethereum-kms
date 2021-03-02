import { KMSSigner } from "../src/sign/index";
import { Request, AWSError } from "aws-sdk";
import assert from "assert";

describe("KMSSigner unit tests", () => {
  //setup the KMS mocks here
  const credentials = {
    access_key: "testing_acess_key",
    access_secret: "testing_acess_secret",
    region: "testing_region",
    key_id: "testing_key_id",
    provider_url: "https://testingnode.com",
    chain: "kovan",
  };
  const expectedResults = {
    der: "DER",
  };
  const kmsSigner = new KMSSigner(
    credentials.access_key,
    credentials.access_secret,
    credentials.region,
    credentials.key_id,
    credentials.provider_url,
    "kovan"
  );

  //Mocks
  kmsSigner.kms.getPublicKey = jest
    .fn()
    .mockImplementation(async (keyId: string) => {
      return new Promise((res, rej) => {
        res("hey there");
      });
    });

  kmsSigner.kms.sign = jest
    .fn()
    .mockImplementation((msgHash: Buffer, keyId: string) => {
      return "This is a signed message";
    });

  it("Should set up the state constant correctly", async () => {
    const { kms } = kmsSigner;
    const kmsconfig = kms.config;
    assert.strictEqual(kmsconfig.accessKeyId, credentials.access_key);
    assert.strictEqual(kmsconfig.secretAccessKey, credentials.access_secret);
    assert.strictEqual(kmsconfig.region, credentials.region);
    assert.strictEqual(kmsSigner.keyId, credentials.key_id);
    const web3provider = kmsSigner.web3.currentProvider;
    //@ts-ignore
    assert.strictEqual(web3provider.host, credentials.provider_url);
  });
  it("Should be able to get the correct DER public key from the function", async () => {
    console.log(kmsSigner.getPublicKey("yahoo"));
    const der = kmsSigner.getPublicKey(credentials.key_id);
    // assert.strictEqual(der, expectedResults.der);
  });
  it("Should be able to get the correct DER public key from state variable", async () => {
    const der = kmsSigner.pubKey;
    // assert.strictEqual(der, expectedResults.der);
  });
  it("Should be able to get the correct ethereum address", async () => {});
  it("Should be able to generate the correct ethereum sig from signing eth address hash as message ", async () => {});
  it("Should be able to recover back ethereum address with v value of 27 or 28 ", async () => {});
  it("Should be able to set metadata correctly", () => {});
  it("Should be able to sign transaction payload correctly", () => {});
});
