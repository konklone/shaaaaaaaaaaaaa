/**
* shaaa.js
*
* Checks a domain for its certificate algorithm.
*
* Depends on openssl installed and accessible on the PATH.
*/

var exec = require("child_process").exec;

var Shaaa = {
  algorithms: [
    // new gold standards
    "sha256", "sha224", "sha384", "sha512",

    "sha1", // common, but deprecated
    "md5", // old, broken
    "md2" // so old, so broken
  ],

  // TODO: sanitize domain here.
  // In the meantime, sanitize domain BEFORE inputting here.
  cmd: function(domain) {
    return "" +
      // piping into openssl tells it not to hold an open connection
      "echo -n" +
      // connect to given domain on port 443
      " | openssl s_client -connect " + domain + ":443" +
      // specify hostname in case server uses SNI
      "   -servername " + domain +
      // yank out just the cert
      " | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'" +
      // extract x509 details from the cert
      " | openssl x509 -text" +
      // look for just the signature algorithm
      " | grep \"Signature Algorithm\""
  },

  // output will look like:
  // '    Signature Algorithm: sha256WithRSAEncryption\n    Signature Algorithm: sha256WithRSAEncryption\n'
  extract: function(stdout) {
    var line = stdout.split("\n")[0].trim();
    var pieces = line.split(" ");
    var raw = pieces[pieces.length - 1];

    for (var i=0; i<Shaaa.algorithms.length; i++) {
      var algorithm = Shaaa.algorithms[i];
      if (raw.indexOf(algorithm) == 0) return algorithm;
    }

    return "unknown";
  },

  from: function(domain, callback) {
    exec(Shaaa.cmd(domain), function(error, stdout, stderr) {
      if (error) return callback(error);

      var answer = Shaaa.extract(stdout);
      var good = (
        (answer == "sha256") ||
        (answer == "sha224") ||
        (answer == "sha384") ||
        (answer == "sha512")
      );

      if (callback)
        callback(null, answer, good);
      else
        console.log(answer);
    });
  }
}

module.exports = Shaaa;
