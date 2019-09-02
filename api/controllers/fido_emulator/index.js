'use strict';

const HELPER_BASE = process.env.HELPER_BASE || '../../helpers/';
const Response = require(HELPER_BASE + 'response');
const Redirect = require(HELPER_BASE + 'redirect');

const ECDSA = require('ecdsa-secp256r1')
const x509 = require('js-x509-utils');
const crypto = require('crypto');

const curveLength = Math.ceil(256 / 8);

const FIDO_ISSUER = process.env.FIDO_ISSUER || 'FT FIDO 0200';
const FIDO_SUBJECT = process.env.FIDO_SUBJECT || 'FT FIDO P2047001341412';
const FIDO_EXPIRE = Number(process.env.FIDO_EXPIRE) || 365;

var total_counter = Number(process.env.COUNTER_START) || 0;
var total_application_id = Number(process.env.APPLICATION_ID_START) || 1;

exports.handler = async (event, context, callback) => {
  if( event.path == "/device/u2f_register"){
    var body = JSON.parse(event.body);
    
    var result = await u2f_register(Buffer.from(body.challenge, 'hex'), Buffer.from(body.application, 'hex'));

    return new Response({
      result: result.toString('hex')
    });
  }else
  if( event.path == "/device/u2f_authenticate"){
    var body = JSON.parse(event.body);

    var result = await u2f_authenticate(body.control, Buffer.from(body.challenge, 'hex'), Buffer.from(body.application, 'hex'), Buffer.from(body.key_handle, 'hex'))

    return new Response({
      result: result.toString('hex')
    });
  }else
  if( event.path == "/device/u2f_version"){

    var result = await u2f_version();
    return new Response({
      result: result.toString('hex')
    });
  }
};

async function u2f_register(challenge, application){
  // 楕円暗号公開鍵ペアの作成
  var ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();

  var pubkey = ecdh.getPublicKey();
  var privkey = ecdh.getPrivateKey();
  var privateKey = new ECDSA({
    d: privkey,
    x: pubkey.slice(1, 1 + curveLength),
    y: pubkey.slice(1 + curveLength)
  });

  var userPublicKey = pubkey;

  // 内部管理用のアプリケーションIDの決定
  console.log('application_id='+ total_application_id);

  // KeyHandleの作成
  var keyHandle = Buffer.concat([Buffer.from([(total_application_id >> 24) & 0xff, (total_application_id >> 16) & 0xff, (total_application_id >> 8) & 0xff, total_application_id & 0xff]), privkey] );
  total_application_id++;
  var keyLength = Buffer.from([keyHandle.length]);

  // X.509証明書の作成
  var attestationCert = await x509.fromJwk(
    privateKey.asPublic().toJWK(),
    privateKey.toJWK(),
    'der',
    {
      signature: 'ecdsa-with-sha256',
      days: FIDO_EXPIRE,
      issuer: { commonName: FIDO_ISSUER },
      subject: { commonName: FIDO_SUBJECT },
    },
  );

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
  console.log('control=' + control);

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
  total_counter++;
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
