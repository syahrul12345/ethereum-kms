# Ethereum-KMS

Ethereum-KMS is a javascript library to allow applications to use Amazon Key Management Service (KMS) as a signer. This ensures that the private key never leaves a hardware store managed by AWS, achieving enterprise grade security.

Use this library when your application will be managing the signing process for your users.

## Installation

```
yarn add ethereum-kms
```


## Usage

You will need an amazon aws account, and you are required to create an assymetric key, used for signing and verifying in the KMS dashboard. Select the secp256k1 implementation in the KMS console. Add an IAM user to be able to access this key. 


To use simply: 

```
import { TxData } from "ethereumjs-tx";
import { KMSSigner } from "ethereum-kms";
const main = async () => {
  const signer = new KMSSigner(
    "access_key_id",   // acess_key_id of your IAM user with access to the key.
    "access_secret",   // acess_secret. 
    "ap-southeast-1",  //region 
    "KEY_ID",          //key id of the KMS key for your application user.
    "INFURA_PROVIDER", //Node provider   
    "CHAIN_NAME"       // Chain name. mainnet, kovan or ropsten
  );

  // The payload we want to sign with the private
  const payload: TxData = {
    nonce: 0,
    gasPrice: "0x0918400000",
    gasLimit: 160000,
    to: "0x0000000000000000000000000000000000000000",
    value: "0x00",
    data: "0x00",
  };
  signer.sendPayload(payload);
};

main();
```