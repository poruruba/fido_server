'use strict';

const HELPER_BASE = process.env.HELPER_BASE || '../../helpers/';
const Response = require(HELPER_BASE + 'response');
const Redirect = require(HELPER_BASE + 'redirect');

const rs = require('jsrsasign');
const ECDSA = require('ecdsa-secp256r1')
const crypto = require('crypto');

const curveLength = Math.ceil(256 / 8);

const FIDO_ISSUER = process.env.FIDO_ISSUER || 'FT FIDO 0200';
const FIDO_SUBJECT = process.env.FIDO_SUBJECT || 'FT FIDO P2000000000000';
const FIDO_EXPIRE = Number(process.env.FIDO_EXPIRE) || 365;

var total_counter = Number(process.env.COUNTER_START) || 0;
var total_application_id = Number(process.env.APPLICATION_ID_START) || 1;

// X509証明書の楕円暗号公開鍵ペアの作成
var kp_cert = rs.KEYUTIL.generateKeypair('EC', 'secp256r1');

exports.handler = async (event, context, callback) => {
  if( event.path == "/device/u2f_register"){
    var body = JSON.parse(event.body);
    console.log(body);
    
    var input = Buffer.from(body.input, 'hex');
    var result = await u2f_register(input.subarray(7, 7 + 32), input.subarray(7 + 32, 7 + 32 + 32));
    
    return new Response({
      result: Buffer.concat([ result, Buffer.from([0x90, 0x00])]).toString('hex')
    });
  }else
  if( event.path == "/device/u2f_authenticate"){
    var body = JSON.parse(event.body);
    console.log(body);

    var input = Buffer.from(body.input, 'hex');
    var result = await u2f_authenticate(input[2], input.subarray(7, 7 + 32), input.subarray(7 + 32, 7 + 32 + 32), input.subarray(7 + 32 + 32 + 1, 7 + 32 + 32 + 1 + input[7 + 32 + 32]));

    return new Response({
      result: Buffer.concat([ result, Buffer.from([0x90, 0x00])]).toString('hex')
    });
  }else
  if( event.path == "/device/u2f_version"){
    var result = await u2f_version();
    return new Response({
      result: Buffer.concat([ result, Buffer.from([0x90, 0x00])]).toString('hex')
    });
  }
};

async function u2f_register(challenge, application){
  // 楕円暗号公開鍵ペアの作成
  var kp = rs.KEYUTIL.generateKeypair('EC', 'secp256r1');

  var pubkey = Buffer.from(kp.pubKeyObj.pubKeyHex, 'hex');
  var privkey = Buffer.from(kp.prvKeyObj.prvKeyHex, 'hex');
  var privateKey = new ECDSA({
    d: privkey,
    x: pubkey.slice(1, 1 + curveLength),
    y: pubkey.slice(1 + curveLength)
  });
  var userPublicKey = pubkey;

  // 内部管理用のアプリケーションIDの決定
  console.log('application_id='+ total_application_id);

  // KeyHandleの作成
  var keyHandle = Buffer.concat([Buffer.from([(total_application_id >> 24) & 0xff, (total_application_id >> 16) & 0xff, (total_application_id >> 8) & 0xff, total_application_id & 0xff]),  				privkey] );
  total_application_id++;
  var keyLength = Buffer.from([keyHandle.length]);

  // X.509証明書の作成
  var tbsc = new rs.KJUR.asn1.x509.TBSCertificate();

  tbsc.setSerialNumberByParam({'int': 1234});
  tbsc.setSignatureAlgByParam({'name': 'SHA256withECDSA'});
  tbsc.setIssuerByParam({'str': "/CN=FT FIDO 0200"});  
  tbsc.setNotBeforeByParam({'str': "190511235959Z"});
  tbsc.setNotAfterByParam({'str': "340511235959Z"});
  tbsc.setSubjectByParam({'str': "/CN=FT FIDO P2000000000000"});  
  tbsc.setSubjectPublicKey(kp.pubKeyObj);

/*
  //サブジェクトキー識別子
  var extSKI = new rs.KJUR.asn1.x509.Extension();
  extSKI.oid = '2.5.29.14';
  const ski = rs.KJUR.crypto.Util.hashHex(kp.pubKeyObj.pubKeyHex, 'sha1');
  const derSKI = new rs.KJUR.asn1.DEROctetString({ hex: ski });
  extSKI.getExtnValueHex = () => {return derSKI.getEncodedHex() };
  tbsc.appendExtension(extSKI);
*/

  // FIDO U2F certificate transports extension
  var extSKI2 = new rs.KJUR.asn1.x509.Extension();
  extSKI2.oid = '1.3.6.1.4.1.45724.2.1.1';
  extSKI2.getExtnValueHex = () => { return "03020640" };
  tbsc.appendExtension(extSKI2);
    
  var cert = new rs.KJUR.asn1.x509.Certificate({'tbscertobj': tbsc, 'prvkeyobj': kp_cert.prvKeyObj });
  cert.sign();
  var attestationCert = Buffer.from(cert.hTLV, 'hex');
  
  // 署名の生成
  var input = Buffer.concat([
    Buffer.from([0x00]),
    application,
    challenge,
    keyHandle,
    userPublicKey
  ]);
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(input);
  var signature = sign.sign(privateKey.toPEM());
  
  console.log('userPublicKey(' + userPublicKey.length + ')=' + userPublicKey.toString('hex'));
  console.log('keyHandle(' + keyHandle.length + ')=' + keyHandle.toString('hex'));
  console.log('attestationCert(' + attestationCert.length + ')=' + attestationCert.toString('hex'));
  console.log('signature(' + signature.length + ')=' + signature.toString('hex'));

  // レスポンスの生成(concat)
  return Buffer.concat([
    Buffer.from([0x05]),
    userPublicKey,
    keyLength,
    keyHandle,
    attestationCert,
    signature
  ]);
}

async function u2f_authenticate(control, challenge, application, keyHandle){
  console.log('control=', control);

  var userPresence = Buffer.from([0x01]);

  // 内部管理用のアプリケーションIDの抽出
  var application_id = (keyHandle.readUInt8(0) << 24) | (keyHandle.readUInt8(1) << 16) | (keyHandle.readUInt8(2) << 8) | keyHandle.readUInt8(3);
  console.log('application_id=' + application_id);

  // 楕円暗号公開鍵ペアの復元
  var ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(keyHandle.slice(4));

  var pubkey = ecdh.getPublicKey();
  var privkey = ecdh.getPrivateKey();
  var privateKey = new ECDSA({
    d: privkey,
    x: pubkey.slice(1, 1 + curveLength),
    y: pubkey.slice(1 + curveLength)
  })

  // 署名回数カウンタの決定
  ++total_counter;
  console.log('total_counter=' + total_counter);
  var counter = Buffer.from([ (total_counter >> 24) & 0xff, (total_counter >> 16) & 0xff, (total_counter >> 8) & 0xff, total_counter & 0xff ])

  // 署名生成
  var input = Buffer.concat([
    application, 
    userPresence,
    counter,
    challenge
  ]);
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(input);
  var signature = sign.sign(privateKey.toPEM());

  console.log('input(' + input.length + ')=' + input.toString('hex'));
  console.log('sigunature(' + signature.length + ')=' + signature.toString('hex'));

  // verify sample code
/*  
  const verify = crypto.createVerify('RSA-SHA256')
  verify.write(input)
  verify.end();

  var result =  verify.verify(
    privateKey.asPublic().toPEM(),
    signature
  );
  console.log('verify result=' + result);
*/

  // レスポンスの生成(concat)
  return Buffer.concat([
    userPresence,
    counter,
    signature
  ]);
}

async function u2f_version(){
  var version = Buffer.from('U2F_V2');
  return Promise.resolve(version);
}
