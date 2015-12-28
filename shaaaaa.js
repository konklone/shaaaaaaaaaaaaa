/**
* shaaaaa.js
*
* Checks a domain for its certificate algorithm.
*
* Depends on openssl installed and accessible on the PATH.
*/

// used to call out to openssl
var exec = require("child_process").exec;
var fs = require('fs'); // loads root certs

// yorkie's fork, includes signatureAlgorithm
var x509 = require("x509");

var net = require('net');
var forge = require('node-forge');

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

    var certsarray = [];

    var socket = new net.Socket();
    var client = forge.tls.createConnection({
      server: false,

      verify: function(connection, verified, depth, certs) {
        if (options.verbose || options.debug) console.log('[tls] parsing cert at depth '+depth);

        // pick out a few fields we want from the cert
        var signatureAlgorithm = forge.pki.oids[certs[depth].signatureOid]; // looks up the sig in OID table
        var commonName = certs[depth].subject.getField('CN').value;
        var notAfter = certs[depth].validity.notAfter;

        // determine SHA1 and SHA256 fingerprints of the cert
        var asn1 = forge.pki.certificateToAsn1(certs[depth]);
        var der = forge.asn1.toDer(asn1);
        var sha1 = forge.md.sha1.create();
        var sha256 = forge.md.sha256.create();
        sha1.update(der.bytes());
        sha256.update(der.bytes());

        var fingerprintSHA1 = sha1.digest().toHex();
        var fingerprintSHA256 = sha256.digest().toHex();

        // push our simplified cert object into certsarray
        certsarray.push({
          signatureAlgorithm: signatureAlgorithm,
          commonName: commonName,
          notAfter: notAfter,
          fingerPrint: {
            sha1: fingerprintSHA1,
            sha256: fingerprintSHA256
          }
        });
        return true;
      },

      connected: function(connection) {
        // prepare data to be sent TLS encrypted
        if (options.verbose || options.debug) console.log('[tls] connected');
        client.prepare('HEAD / HTTP/1.0\r\n\r\n'); // TODO: can we get certs without having to send this?
      },

      tlsDataReady: function(connection) {
        // send TLS encrypted data
        var data = connection.tlsData.getBytes();
        socket.write(data, 'binary');
      },

      dataReady: function(connection) {
        // retrieve response from server
        var data = connection.data.getBytes();
        if (options.verbose || options.debug) console.log('[tls] data received: '+data);
      },

      closed: function() {
        if (options.verbose || options.debug) console.log('[tls] disconnected');
      },

      error: function(connection, error) {
        if (options.verbose || options.debug) console.log('[tls] error ', error);
        if (error.send == true)
          socket.destroy();
      }
    });

    socket.on('connect', function() {
      if (options.verbose || options.debug) console.log('[socket] connected');
      client.handshake();
    });

    socket.on('data', function(data) {
      client.process(data.toString('binary'));
    });

    socket.on('error', function(error) {
      if (options.verbose || options.debug) console.log('[socket] error ', error);
      callback({message: error});
      return;
    });

    socket.on('end', function() {
      if (options.verbose || options.debug) console.log('[socket] disconnected');

      if (certsarray.length == 0) {
        callback({message: "No certs returned"});
        return;
      } else
        callback(null, certsarray);
    });

    // connect to domain.  get the certificate(s).
    socket.connect(port, domain);

    // this is to catch-all for any hangs.
    socket.setTimeout(3000, function() {
      socket.destroy();
      if (options.verbose || options.debug) console.log('[socket] timeout');
      callback({message: "Could not establish any connection to "+domain});
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
    // var cert = x509.parseCert(text);
    var answer = Shaaa.algorithm(cert.signatureAlgorithm);

/* skip this isRoot() thing for a minute...
    var root = Shaaa.isRoot(cert);
    var replacement = (root ? null : Shaaa.sha2URL(cert.fingerPrint));
*/

    var root = null;
    var replacement = null;

    return {
      algorithm: answer.algorithm,
      raw: answer.raw,
      good: (root || answer.good),
//      root: root,
//      replacement: replacement,

      expires: cert.notAfter,
      name: cert.commonName
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
