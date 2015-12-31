/**
* shaaaaa.js
*
* Checks a domain for its certificate algorithm.
*
*/

var fs = require('fs'); // loads root certs

// yorkie's fork, includes signatureAlgorithm
var x509 = require("x509");

var tls = require('tls');
var openssl = require('openssl-wrapper');

var Shaaa = {

  // root cert bundle, loaded when this file is required
  roots: null,

  // load root bundle, parse each cert
  loadRoots: function() {
    Shaaa.roots = [];

    // store a fingerprint of each one
    var certs = fs.readFileSync(__dirname + "/ca-bundle.crt", "utf-8").split("\n\n");
    for (var i=0; i<certs.length; i++)
      Shaaa.roots.push(x509.parseCert(certs[i]).fingerPrint);
  },

  // takes x509-parsed cert, compares fingerprint
  isRoot: function(cert) {
    return (Shaaa.roots.indexOf(cert.fingerPrint) > -1);
  },

  // fingerprints of SHA-1 intermediate certs with known SHA-2 replacements
  fingerprints: null,
  loadFingerprints: function() {
    Shaaa.fingerprints = JSON.parse(fs.readFileSync(__dirname + '/fingerprints.json', 'utf-8')).certificates;
  },

  algorithms: [
    // new gold standards
    "sha256", "sha224", "sha384", "sha512",

    "sha1", // common, but deprecated
    "md5", // old, broken
    "md2" // so old, so broken
  ],

  // given e.g. 'sha256WithRSAEncryption', return
  // {algorithm: 'sha256', raw: 'sha256WithRSAEncryption', good: true}
  algorithm: function(raw) {
    var raw_compare = raw.toLowerCase();

    var answer;
    for (var i=0; i<Shaaa.algorithms.length; i++) {
      var algorithm = Shaaa.algorithms[i];
      if (raw_compare.indexOf(algorithm) == 0) answer = algorithm;
      if (raw_compare == ("ecdsa-with-" + algorithm)) answer = algorithm;
    }
    if (!answer) answer = "unknown";

    var good = (
      (answer == "sha256") ||
      (answer == "sha224") ||
      (answer == "sha384") ||
      (answer == "sha512")
    );

    return {algorithm: answer, raw: raw, good: good};
  },

  // using openssl to convert DER encoded cert to PEM format
  derToPem: function(derBuffer, callback) {
    openssl.exec('x509', derBuffer, { inform: 'der', outform: 'pem' }, function(error, pemBuffer) {
      if (error)
        callback(error);
      else
        callback(null, pemBuffer);
    });
  },

  certs: function(domain, callback, options) {
    if (!options) options = {};

    options = { verbose: true };

    var defaultport = 443;
    var matchdomain = domain.match(/^[\w\.\-\:]+$/);
    // make sure domain looks valid, look for a port otherwise use defaultport
    if (matchdomain) {
      var matchport = domain.match(/([^:]+):(\d+)$/);
      if (matchport) {
        domain = matchport[1];
        port = matchport[2];
      } else {
        port = defaultport;
      }
    } else {
      callback({message: "Invalid domain"});
      return;
    }

    var peerCert = {};

    var tlsOptions = {
      host: domain,
      port: port,
      rejectUnauthorized: false
    };

/*
[tlsSocket] connected
{ subject: 
   { C: 'US',
     ST: 'NY',
     L: 'Rochester',
     O: 'Netsville, Inc.',
     OU: 'Wildcard Division',
     CN: '*.netsville.com' },
  issuer: 
   { C: 'US',
     O: 'DigiCert Inc',
     OU: 'www.digicert.com',
     CN: 'DigiCert SHA2 High Assurance Server CA' },
  subjectaltname: 'DNS:*.netsville.com, DNS:netsville.com',
  infoAccess: 
   { 'OCSP - URI': [ 'http://ocsp.digicert.com' ],
     'CA Issuers - URI': [ 'http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt' ] },
  modulus: 'C7013C205D7..........B3C8765DE4AD9D39',
  exponent: '10001',
  valid_from: 'Jun 28 00:00:00 2015 GMT',
  valid_to: 'Jul 11 12:00:00 2016 GMT',
  fingerprint: '74:9F:95:D7:A5:4B:3B:06:59:32:2A:97:D1:A0:37:7D:93:A6:F3:02',
  ext_key_usage: [ '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2' ],
  serialNumber: '03CB385EB2961C88233799B4C7439548',
  raw: <Buffer>,
  issuerCertificate: 
   { subject: 
      { C: 'US',
        O: 'DigiCert Inc',
        OU: 'www.digicert.com',
        CN: 'DigiCert SHA2 High Assurance Server CA' },
     issuer: 
      { C: 'US',
        O: 'DigiCert Inc',
        OU: 'www.digicert.com',
        CN: 'DigiCert High Assurance EV Root CA' },
     infoAccess: { 'OCSP - URI': [Object] },
     modulus: 'B6E02FC22406C8..................6892532F5EE3',
     exponent: '10001',
     valid_from: 'Oct 22 12:00:00 2013 GMT',
     valid_to: 'Oct 22 12:00:00 2028 GMT',
     fingerprint: 'A0:31:C4:67:82:E6:E6:C6:62:C2:C8:7C:76:DA:9A:A6:2C:CA:BD:8E',
     ext_key_usage: [ '1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2' ],
     serialNumber: '04E1E7A4DC5CF2F36DC02B42B85D159F',
     raw: <Buffer>,
     issuerCertificate: 
      { subject: [Object],
        issuer: [Object],
        modulus: 'C6CCE573E6FBD87................5D1A500B2012CC41BB6E0B5138B84BCB',
        exponent: '10001',
        valid_from: 'Nov 10 00:00:00 2006 GMT',
        valid_to: 'Nov 10 00:00:00 2031 GMT',
        fingerprint: '5F:B7:EE:06:33:E2:59:DB:AD:0C:4C:9A:E6:D3:8F:1A:61:C7:DC:25',
        serialNumber: '02AC5C266A0B409B8F0B79F2AE462577',
        raw: <Buffer>,
        issuerCertificate: [Circular] } } }
*/

    var socket = tls.connect(tlsOptions, function() {
      if (options.verbose || options.debug) console.log('[tlsSocket] connected');
      peerCert = socket.getPeerCertificate(true);
      socket.end();
    });

    socket.setEncoding('utf8');
    socket.on('end', function() {
      if (options.verbose || options.debug) console.log('[tlsSocket] disconnected');

      // process peerCert and all the issuer certs inside it
      // console.log(peerCert);
      var certsarray = [];

      Shaaa.derToPem(peerCert.raw, function(err, pem) {
        var pemCert = x509.parseCert(pem.toString());
        // console.log(pemCert);
        certsarray.push(pemCert);
        if (certsarray.length == 0)
          callback({message: "No certs returned"});
        else
          callback(null, certsarray);
      });
    });

    socket.on('error', function(error) {
      if (options.verbose || options.debug) console.log('[tlsSocket] error ', error);
      callback({message: error});
      return;
    });

    // this is to catch-all for any hangs.
    socket.setTimeout(3000, function() {
      socket.destroy();
      if (options.verbose || options.debug) console.log('[tlsSocket] timeout');
      callback({message: "Could not establish a connection to "+domain});
      return;
    });
  },

  sha2URL: function(fingerprint) {
    for (var i=0; i<Shaaa.fingerprints.length; i++) {
      if (Shaaa.fingerprints[i].sha1 == fingerprint)
        return Shaaa.fingerprints[i].url;
    }
  },

  cert: function(cert) {
    var answer = Shaaa.algorithm(cert.signatureAlgorithm);

    // var root = Shaaa.isRoot(cert);
    // var replacement = (root ? null : Shaaa.sha2URL(cert.fingerPrint));

    var root = null;
    var replacement = null;

    return {
      algorithm: answer.algorithm,
      raw: answer.raw,
      good: (root || answer.good),
//      root: root,
//      replacement: replacement,

      expires: cert.notAfter,
      name: cert.subject.commonName
    };
  },

  /**
  * Desired output:
  * {
  *   domain: shaaaaaaaaaaaaa.com,
  *   cert: {
  *     algorithm: 'sha256',
  *     raw: 'sha256WithRSAEncryption',
  *     good: true,
  *     root: false,
  *     replacement: null,
  *     expires: Tue Aug 18 2015 19:59:59 GMT-0400 (EDT),
  *     name: "www.konklone.com"
  *   },
  *   intermediates: [
  *     { ... } // same form as above
  *   ]
  * }
  */

  from: function(domain, callback, options) {
    if (!options) options = {};

    var data = {domain: domain};

    Shaaa.certs(domain, function(error, certs) {
      if (error) return callback(error);

      data.cert = Shaaa.cert(certs[0]);

      data.intermediates = [];
      certs.slice(1).forEach(function(cert) {
        data.intermediates.push(Shaaa.cert(cert));
      });

      var intergood = true;
      for (var i=0; i<data.intermediates.length; i++) {
        if (!data.intermediates[i].good) {
          if (i == 0) {
            intergood = false;
            break;
          }
        }
      }

      if (data.cert.good && intergood)
        data.diagnosis = "good";
      else if (data.cert.good && !intergood)
        data.diagnosis = "almost";
      else
        data.diagnosis = "bad";

      if (callback)
        callback(null, data);
      else
        console.log(data);
    }, options);
  }
}

// load roots and fingerprints on first require
// Shaaa.loadRoots();
Shaaa.loadFingerprints();

module.exports = Shaaa;
