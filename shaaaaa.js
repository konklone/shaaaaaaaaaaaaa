/**
* shaaaaa.js
*
* Checks a domain for its certificate algorithm.
*
*/

var fs = require('fs'); // loads root certs

// yorkie's fork, includes signatureAlgorithm
var x509 = require("x509");

// network cxn handled directly by tls
var tls = require('tls');

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

  // Convert DER certificate to PEM
  derToPem: function(derBuffer) {
    var b64Der = derBuffer.toString('base64');
    var b64DerLines = b64Der.match(/.{1,64}/g);
    return "-----BEGIN CERTIFICATE-----\n" + b64DerLines.join('\n') + "\n-----END CERTIFICATE-----\n";
  },

  certs: function(domain, callback, options) {
    if (!options) options = {};

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

    var socket = tls.connect(tlsOptions, function() {
      if (options.verbose || options.debug) console.log('[tlsSocket] connected');
      peerCert = socket.getPeerCertificate(true);
      socket.end();
    });

    socket.setEncoding('utf8');
    socket.on('end', function() {
      if (options.verbose || options.debug) console.log('[tlsSocket] disconnected');

      // Walk through peerCert object.  Grab DER-encoded certs.  Convert to PEM and push to certsArray.
      var certsArray = [];
      function eachDer(cert) {
        var pem = Shaaa.derToPem(cert.raw);
        certsArray.push(x509.parseCert(pem));
        if (cert.issuerCertificate !== cert) // peerCert contains circular obj ref.  This stops us.
          eachDer(cert.issuerCertificate);
      }
      eachDer(peerCert);

      if (certsArray.length == 0)
        callback({message: "No certs returned"});
      else
        callback(null, certsArray);
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

    var root = Shaaa.isRoot(cert);
    var replacement = (root ? null : Shaaa.sha2URL(cert.fingerPrint));

    var root = null;
    var replacement = null;

    return {
      algorithm: answer.algorithm,
      raw: answer.raw,
      good: (root || answer.good),
      root: root,
      replacement: replacement,

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
Shaaa.loadRoots();
Shaaa.loadFingerprints();

module.exports = Shaaa;
