import { KMSSigner } from "../src/sign/index";
import { KMS } from "aws-sdk";
describe("KMSSigner unit tests", () => {
  //setup the KMS mocks here
  const kms = new KMS();
  kms.getPublicKey = jest.fn().mockImplementation(() => {
    return "This is a public key";
  });
  kms.sign = jest.fn().mockImplementation((msgHash: Buffer, keyId: string) => {
    return "This is a signed message";
  });
  const kmsSigner = new KMSSigner("", "", "", "", "", "kovan");
  kmsSigner.kms = kms;

  it("Should set up the state constant correctly", async () => {});
  it("Should be able to get the correct DER public key", async () => {});
  it("Should be able to get the correct ethereum address", async () => {});
  it("Should be able to generate the correct ethereum sig from signing eth address hash as message ", async () => {});
  it("Should be able to recover back ethereum address with v value of 27 or 28 ", async () => {});
  it("Should be able to set metadata correctly", () => {});
  it("Should be able to sign transaction payload correctly", () => {});
});
