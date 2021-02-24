Usage


To use simply: 
```
import { TxData } from "ethereumjs-tx";
import { KMSSigner } from "ethereum-kms";
const main = async () => {
  const signer = new KMSSigner(
    "access_key_id",
    "access_secret",
    "ap-southeast-1",
    "KEY_ID",
    "INFURA_PROVIDER",
    "CHAIN_NAME"
  );
  // The payload we want to sign
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