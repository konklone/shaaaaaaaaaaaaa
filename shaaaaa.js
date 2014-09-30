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

var Shaaa = {

  // root cert bundle, loaded when this file is required
  roots: null,

  // load root bundle, parse each cert
  loadRoots: function() {
    Shaaa.roots = [];

    // store a fingerprint of each one
    var certs = fs.readFileSync("./ca-bundle.crt", "utf-8").split("\n\n");
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
    Shaaa.fingerprints = JSON.parse(fs.readFileSync('./fingerprints.json', 'utf-8')).certificates;
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

    // This accounts for -servername/SNI, which cannot have a port
    var server_name = domain.replace(/[^\w\.\-]|[$:\d+]/g, '');

    // This accounts for -connect, which can have a port
    var server_connect = domain.replace(/[^\w\.\-:]/g, '');

    // If the address does not have a port defined, add default :443
    if (server_connect.match(/:\d+^/g) === null) {
      server_connect += ":443";
    }

    // adapted from http://askubuntu.com/a/201923/3096
    var command = "" +
      // piping into openssl tells it not to hold an open connection
      "echo -n" +
      // connect to given domain on port 443
      " | openssl s_client -connect " + server_connect +
      // specify hostname in case server uses SNI
      " -servername " + server_name +
      // ask for the full cert chain
      " -showcerts";

    if (options.verbose || options.debug) console.log(command + "\n");

    exec(command, function(error, stdout, stderr) {
      if (error) return callback(error);

      // stdout is a long block of openssl output - grab the certs
      var certs = [];
      // using multiline workaround: http://stackoverflow.com/a/1068308/16075
      var regex = /(\-+BEGIN CERTIFICATE\-+[\s\S]*?\-+END CERTIFICATE\-+)/g

      var match = regex.exec(stdout);
      while (match != null) {
        certs.push(match[1]);
        match = regex.exec(stdout);
      }

      callback(null, certs);
    });
  },

  sha2URL: function(fingerprint) {
    for (var i=0; i<Shaaa.fingerprints.length; i++) {
      if (Shaaa.fingerprints[i].sha1 == fingerprint)
        return Shaaa.fingerprints[i].url;
    }
  },

  cert: function(text) {
    var cert = x509.parseCert(text);
    var answer = Shaaa.algorithm(cert.signatureAlgorithm);
    var root = Shaaa.isRoot(cert);
    var replacement = (root ? null : Shaaa.sha2URL(cert.fingerPrint));

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
