import { KMS } from "aws-sdk";
import { keccak256 } from "js-sha3";
import * as ethutil from "ethereumjs-util";
import Web3 from "web3";
import BN from "bn.js";
import { Transaction, TxData } from "ethereumjs-tx";
import { TransactionReceipt } from "web3-core/types";
const asn1 = require("asn1.js");

export class KMSSigner {
  kms: KMS;
  web3: Web3;
  keyId: string;
  EcdsaSigAsnParse: any;
  EcdsaPubKey: any;
  chain: "mainnet" | "kovan" | "ropsten";
  pubKey: any;
  ethAddr: any;
  sig: any;
  recoveredPubAddr: any;
  constructor(
    access_key_id: string,
    access_secret: string,
    region: string,
    key_id: string,
    providerURL: string,
    chain: "mainnet" | "kovan" | "ropsten"
  ) {
    this.kms = new KMS({
      accessKeyId: access_key_id, // credentials for your IAM user with KMS access
      secretAccessKey: access_secret, // credentials for your IAM user with KMS access
      region: region,
      apiVersion: "2014-11-01",
    });

    this.web3 = new Web3(new Web3.providers.HttpProvider(providerURL));
    this.keyId = key_id;

    this.EcdsaSigAsnParse = asn1.define("EcdsaSig", function (this: any) {
      // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
      this.seq().obj(this.key("r").int(), this.key("s").int());
    });

    this.EcdsaPubKey = asn1.define("EcdsaPubKey", function (this: any) {
      // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
      this.seq().obj(
        this.key("algo")
          .seq()
          .obj(this.key("a").objid(), this.key("b").objid()),
        this.key("pubKey").bitstr()
      );
    });
    this.chain = chain;
  }

  sign = async (msgHash: Buffer, keyId: string) => {
    const params: KMS.SignRequest = {
      // key id or 'Alias/<alias>'
      KeyId: keyId,
      Message: msgHash,
      // 'ECDSA_SHA_256' is the one compatible with ECC_SECG_P256K1.
      SigningAlgorithm: "ECDSA_SHA_256",
      MessageType: "DIGEST",
    };
    const res = await this.kms.sign(params).promise();
    return res;
  };

  getPublicKey = async (keyPairId: string) => {
    return this.kms
      .getPublicKey({
        KeyId: keyPairId,
      })
      .promise();
  };

  getEthereumAddress = (publicKey: Buffer): string => {
    // The public key is ASN1 encoded in a format according to
    // https://tools.ietf.org/html/rfc5480#section-2
    // I used https://lapo.it/asn1js to figure out how to parse this
    // and defined the schema in the EcdsaPubKey object
    let res = this.EcdsaPubKey.decode(publicKey, "der");
    let pubKeyBuffer: Buffer = res.pubKey.data;

    // The public key starts with a 0x04 prefix that needs to be removed
    // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
    pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

    const address = keccak256(pubKeyBuffer); // keccak256 hash of publicKey
    const buf2 = Buffer.from(address, "hex");
    const EthAddr = "0x" + buf2.slice(-20).toString("hex"); // take last 20 bytes as ethereum adress
    return EthAddr;
  };

  findEthereumSig = async (plaintext: Buffer) => {
    //Get the signature from kms
    let signature = await this.sign(plaintext, this.keyId);
    if (signature.Signature == undefined) {
      throw new Error("Signature is undefined.");
    }

    let decoded = this.EcdsaSigAsnParse.decode(signature.Signature, "der");
    let r: BN = decoded.r;
    let s: BN = decoded.s;

    let tempsig = r.toString(16) + s.toString(16);

    let secp256k1N = new BN(
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16
    ); // max value on the curve
    let secp256k1halfN = secp256k1N.div(new BN(2)); // half of the curve
    // Because of EIP-2 not all elliptic curve signatures are accepted
    // the value of s needs to be SMALLER than half of the curve
    // i.e. we need to flip s if it's greater than half of the curve
    if (s.gt(secp256k1halfN)) {
      // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
      // if s < half the curve we need to invert it
      // s = curve.n - s
      s = secp256k1N.sub(s);
      return { r, s };
    }
    // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
    return { r, s };
  };

  recoverPubKeyFromSig = (msg: Buffer, r: BN, s: BN, v: number) => {
    let rBuffer = r.toBuffer();
    let sBuffer = s.toBuffer();
    let pubKey = ethutil.ecrecover(msg, v, rBuffer, sBuffer);
    let addrBuf = ethutil.pubToAddress(pubKey);
    var RecoveredEthAddr = ethutil.bufferToHex(addrBuf);
    return RecoveredEthAddr;
  };

  findRightKey = (msg: Buffer, r: BN, s: BN, expectedEthAddr: string) => {
    // This is the wrapper function to find the right v value
    // There are two matching signatues on the elliptic curve
    // we need to find the one that matches to our public key
    // it can be v = 27 or v = 28
    let v = 27;
    let pubKey = this.recoverPubKeyFromSig(msg, r, s, v);
    if (pubKey != expectedEthAddr) {
      // if the pub key for v = 27 does not match
      // it has to be v = 28
      v = 28;
      pubKey = this.recoverPubKeyFromSig(msg, r, s, v);
    }
    return { pubKey, v };
  };
  setMetadata = async () => {
    //Returns a DER encoded public key from amazon KMS directly
    this.pubKey = await this.getPublicKey(this.keyId);
    //Calculate the ethereum address from the DER public key
    this.ethAddr = this.getEthereumAddress(this.pubKey.PublicKey as Buffer);
    // Hash of the public key
    let ethAddrHash = ethutil.keccak(Buffer.from(this.ethAddr));
    // Get the signature value by SIGNING the ethaddrhash. This is the first time we are signing. We merely want the r and s
    // Asks KMS to sign the payload
    // KMS returns DER encoded signature
    // Decompress and calculate r and s
    // Invert if s is larger than the half of secp256k1
    // We get the finalized script
    this.sig = await this.findEthereumSig(ethAddrHash);
    //Try to recover ethereum address given the signature, and we choose if its 27 or 28 from the r and s
    this.recoveredPubAddr = this.findRightKey(
      ethAddrHash,
      this.sig.r,
      this.sig.s,
      this.ethAddr
    );
  };
  signPayload = async (payload: TxData) => {
    // The payload we want to sign
    // We put it with the dummy r,s,v so that we can serialized the FROM field
    const txParams: TxData = {
      nonce: payload.nonce
        ? payload.nonce
        : await this.web3.eth.getTransactionCount(this.ethAddr),
      ...payload,
      r: this.sig.r.toBuffer(),
      s: this.sig.s.toBuffer(),
      v: this.recoveredPubAddr.v,
    };
    const tx = new Transaction(txParams, {
      chain: this.chain,
    });
    let txHash = tx.hash(false);
    //We sign the payload that we want and this will create the correct r and s
    const correctSig = await this.findEthereumSig(txHash);
    const correctRecoveredPubAddr = this.findRightKey(
      txHash,
      correctSig.r,
      correctSig.s,
      this.ethAddr
    );
    tx.r = correctSig.r.toBuffer();
    tx.s = correctSig.s.toBuffer();
    tx.v = new BN(correctRecoveredPubAddr.v).toBuffer();
    const serializedTx = tx.serialize().toString("hex");
    return "0x" + serializedTx;
  };

  sendPayload = async (payload: TxData) => {
    const signedString = await this.signPayload(payload);
    return this.web3.eth.sendSignedTransaction(signedString);
  };
}
