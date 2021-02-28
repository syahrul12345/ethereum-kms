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

  it("We can check if the consumer called the class constructor", async () => {
    const kmsSigner = new KMSSigner("", "", "", "", "", "kovan");
    kmsSigner.kms = kms;
    //Mock
    const res = await kmsSigner.kms.getPublicKey({
      KeyId: "123",
    });

    console.log(res);
  });
});
