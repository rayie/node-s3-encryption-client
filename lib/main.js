var AWS = require("aws-sdk"),
    crypt = require("./crypt"),
    kms = new AWS.KMS(),
    s3 = new AWS.S3();

const metadataCipherAlgorithm = 'x-amz-meta-cipher-algorithm',
      metadataDecryptedEncoding = 'x-amz-meta-decrypted-encoding'
      metadataKmsKeyName = 'x-amz-meta-x-amz-key';

exports.getObject = function(params, callback) {
  var encryptionContext = params.EncryptionContext;
  delete params.EncryptionContext;
  s3.getObject(params, function(err, objectData) {
    if (err) {
      callback(err, null);
    } else {
      var metadata = objectData.Metadata || {};
      var kmsKey = metadata[metadataKmsKeyName];
      if (kmsKey) {
        kms.decrypt({CiphertextBlob: kmsKey, EncryptionContext: encryptionContext}, function(err, kmsData) {
          if (err) {
            callback(err, null);
          } else {
            var helper = new crypt.Helper(kmsData.Plaintext, {algorithm: metadata[metadataCipherAlgorithm], decryptedEncoding: metadata[metadataDecryptedEncoding]});
            objectData.Body = helper.decrypt(objectData.Body);
            delete objectData.Metadata[metadataKmsKeyName];
            delete objectData.Metadata[metadataCipherAlgorithm];
            delete objectData.Metadata[metadataDecryptedEncoding];
            callback(null, objectData);
          }
        });
      } else {
        callback(null, objectData);
      }
    }
  });
}

exports.putObject = function(params, callback) {
  var kmsParams = params.KmsParams
  if (kmsParams && kmsParams.KeyId) {
    kms.generateDataKey(kmsParams, function(err, kmsData) {
      if (err) {
        callback(err, null);
      } else {
        var helper = new crypt.Helper(kmsData.Plaintext, {algorithm: params.CipherAlgorithm, decryptedEncoding: params.DecryptedEncoding});
        params.Body = helper.encrypt(params.Body);
        params.Metadata = params.Metadata || {};
        params.Metadata[metadataKmsKeyName] = kmsData.CiphertextBlob;
        if (params.CipherAlgorithm) params.Metadata[metadataCipherAlgorithm] = params.CipherAlgorithm;
        if (params.DecryptedEncoding) params.Metadata[metadataDecryptedEncoding] = params.DecryptedEncoding;
        putObject(params, callback);
      }
    })
  } else {
    putObject(params, callback);
  }
}

function putObject(params, callback) {
  delete params.KmsParams;
  delete params.CipherAlgorithm;
  delete params.DecryptedEncoding;
  s3.putObject(params, callback);
}