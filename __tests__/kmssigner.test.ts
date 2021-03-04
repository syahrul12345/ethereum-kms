import { KMSSigner } from "../src/sign/index";
import { KMS } from "aws-sdk";
import * as ethutil from "ethereumjs-util";
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
    getPublicKey: {
      KeyId:
        "arn:aws:kms:ap-southeast-1:461975844739:key/4852a344-82b9-44b4-b7e7-f56a3afc9eff",
      PublicKey: new Buffer(
        "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEm9WNxdLWoz3F9CgT0RSRNMKy42LhBEoBRWz8a7IhLJzGwhgVI5zHoALm8Lxll8WczmwPf0bui8fRjwBkkeYajQ==",
        "base64"
      ),
      CustomerMasterKeySpec: "ECC_SECG_P256K1",
      KeyUsage: "SIGN_VERIFY",
      SigningAlgorithms: ["ECDSA_SHA_256"],
    },
    ethereumAddress: "0x1bb96ae2120a095cdeaa3342f25e86222ff5c9a6",
    ethereumAddressHash: "5w7HJpbLCEYY4YgXzLJc24r8597XWcyg/MNRxW7qs0w=",
    signedEthAddress: {
      KeyId:
        "arn:aws:kms:ap-southeast-1:461975844739:key/4852a344-82b9-44b4-b7e7-f56a3afc9eff",
      Signature: new Buffer(
        "MEYCIQDn+CcDQv9ApxIoyfA1NKiQ5+A2w378Yi9kMW8AQA827AIhAMvgtA7CkzlBjT6O3xai2KM94bppHHzXTSbAj1IcT0M4",
        "base64"
      ),
      SigningAlgorithm: "ECDSA_SHA_256",
    },
    r:
      "104922715350842555919824257224514373573099124064913789392680416567701695051500",
    s:
      "23575564520129935969243740549528920211617500405162787489355495716893221125641",
    payload: {
      gasPrice: "0x0918400000",
      gasLimit: 160000,
      to: "0x0000000000000000000000000000000000000000",
      value: "0x00",
      data: "0x00",
    },
    signedPayload:
      "0xf8651f8509184000008302710094000000000000000000000000000000000000000080001ca0bbbaa1fceab57d23f1030f8e365c04af235da66887b21eeb7764040ca29abd78a030290bfe3a8bf43a642526b204ed1b893d2bbd71d9f0b695fd7057692b4f1157",
  };

  const kmsSigner = new KMSSigner(
    credentials.access_key,
    credentials.access_secret,
    credentials.region,
    credentials.key_id,
    credentials.provider_url,
    "kovan"
  );

  class RequestMocker {
    result: any;
    constructor(result: any) {
      this.result = result;
    }
    promise = () => {
      return new Promise((res, rej) => {
        res(this.result);
      });
    };
  }
  //Mocks
  kmsSigner.kms.getPublicKey = jest.fn().mockImplementation((keyId: string) => {
    return new RequestMocker(expectedResults.getPublicKey);
  });

  kmsSigner.kms.sign = jest
    .fn()
    .mockImplementation((params: KMS.SignRequest) => {
      if (
        params.Message.toString("base64") ===
        expectedResults.ethereumAddressHash
      ) {
        return new RequestMocker(expectedResults.signedEthAddress);
      }
      return new RequestMocker(expectedResults.signedPayload);
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
    const publicKey = await kmsSigner.getPublicKey(credentials.key_id);
    assert.strictEqual(publicKey, expectedResults.getPublicKey);
  });

  it("Should be able to get the correct ethereum address", async () => {
    const ethereumAddress = await kmsSigner.getEthereumAddress(
      expectedResults.getPublicKey.PublicKey as Buffer
    );
    assert.strictEqual(ethereumAddress, expectedResults.ethereumAddress);
  });

  it("Should be able to generate the correct ethereum sig from signing eth address hash as message ", async () => {
    let ethAddrHash = ethutil.keccak(
      Buffer.from(expectedResults.ethereumAddress)
    );
    const signedEthereumAddress = await kmsSigner.findEthereumSig(ethAddrHash);
    const r = signedEthereumAddress.r.toString(10);
    const s = signedEthereumAddress.s.toString(10);
    assert.strictEqual(r, expectedResults.r);
    assert.strictEqual(s, expectedResults.s);
  });
  it("Should be able to recover back ethereum address with v value of 27 or 28 ", async () => {});
  it("Should be able to set metadata correctly", () => {});
  it("Should be able to sign transaction payload correctly", () => {});
});
