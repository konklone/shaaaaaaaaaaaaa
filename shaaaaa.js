/**
* shaaaaa.js
*
* Checks a domain for its certificate algorithm.
*
* Depends on openssl installed and accessible on the PATH.
*/

// used to call out to openssl
var exec = require("child_process").exec;

// yorkie's fork, includes signatureAlgorithm
var x509 = require("x.509");

var Shaaa = {
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

    var escaped = domain.replace(/[^\w\.\-]/g, '')

    // adapted from http://askubuntu.com/a/201923/3096
    var command = "" +
      // piping into openssl tells it not to hold an open connection
      "echo -n" +
      // connect to given domain on port 443
      " | openssl s_client -connect " + escaped + ":443" +
      // specify hostname in case server uses SNI
      "   -servername " + escaped +
      // ask for the full cert chain
      "   -showcerts";

    if (options.verbose) console.log(command + "\n");

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

  cert: function(text) {
    var cert = x509.parseCert(text);
    var answer = Shaaa.algorithm(cert.signatureAlgorithm);

    return {
      algorithm: answer.algorithm,
      raw: answer.raw,
      good: answer.good,

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

      if (callback)
        callback(null, data);
      else
        console.log(data);
    }, options);
  }
}

module.exports = Shaaa;
