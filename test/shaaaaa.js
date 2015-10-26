/*
  Meant to be run with faucet:

    npm install -g faucet
    faucet
*/

/*
  These tests are not meant to be run often (e.g. via Travis),
  as they hit the live internet, and hit domains whose security
  properties could change.

  They are here to be used during development and debugging,
  during which other production testing sites should be used
  if something seems to have changed, like SSL Labs.

  TODO: Freeze test cases.
  TODO: Test on Alexa top X for crashes.
*/

var test = require("tape");
var shaaaaa = require("../shaaaaa");

var sites = [
  {
    name: "SHA-2, Comodo 3-chain, konklone.com",
    domain: "konklone.com",
    diagnosis: "good",

    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha384"},
      {good: true, algorithm: "sha384"}
    ]
  },
  {
    name: "SHA-2, StartSSL 2-chain, oversight.io",
    domain: "oversight.io",
    diagnosis: "good",

    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"}
    ]
  },
  {
    name: "SHA-1 with bad IM, facebook.com",
    domain: "facebook.com",
    diagnosis: "bad",

    cert: {good: false, algorithm: "sha1"},
    intermediates: [
      {good: false, algorithm: "sha1"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "SHA-1 with bad IM, google.com",
    domain: "google.com",
    diagnosis: "good",

    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Domain with number, individual8.com",
    domain: "individual8.com",

    diagnosis: "good",
    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"}
    ]
  },
  {
    name: "Domain with number and SNI, teacup.p3k.io",
    domain: "teacup.p3k.io",

    diagnosis: "good",
    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"}
    ]
  },
  {
    name: "Domain with port, google.com:443",
    domain: "google.com:443",

    diagnosis: "good",
    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Domain with number and port, individual8.com:443",
    domain: "individual8.com:443",

    diagnosis: "good",
    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"}
    ]
  },
  {
    name: "Internationalized Domain, domaintest.みんな",
    domain: "domaintest.xn--q9jyb4c",
    diagnosis: "good",

    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Internationalized Domain, اختبارنطاق.شبكة",
    domain: "xn--mgbaacjxy2c4fqb.xn--ngbc5azd",
    diagnosis: "good",

    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "SHA-1 root, sha1-root.jonnybarnes.uk",
    domain: "sha1-root.jonnybarnes.uk",
    diagnosis: "good",

    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: true, algorithm: "sha256"},
      {good: true, algorithm: "sha1", root: true}
    ]
  }
  // {
  //   name: "SHA-1 intermediate with known replacement, penflip.com",
  //   domain: "penflip.com",
  //   diagnosis: "bad",

  //   cert: {good: false, algorithm: "sha1"},
  //   intermediates: [
  //     {good: false, algorithm: "sha1", replacement: "https://www.startssl.com/certs/class1/sha2/pem/sub.class1.server.sha2.ca.pem"}
  //   ]
  // }
];

sites.forEach(function(site) {
  test(site.name, function(t) {
    shaaaaa.from(site.domain, function(err, answer) {
      if (err) t.fail("Error checking domain: " + err);

      t.equal(answer.domain, site.domain, "Domain mismatch.");

      t.equal(answer.cert.algorithm, site.cert.algorithm, "Wrong client algorithm.");
      t.equal(answer.cert.good, site.cert.good, "Wrong client diagnosis.");

      if (site.cert.root) t.ok(answer.cert.root);

      if (site.intermediates) {
        for (var i=0; i<answer.intermediates.length; i++) {
          t.equal(answer.intermediates[i].good, site.intermediates[i].good, "Intermediate " + i + ": wrong diagnosis.")
          t.equal(answer.intermediates[i].algorithm, site.intermediates[i].algorithm, "Intermediate " + i + ": wrong algorithm.")

          if (site.intermediates[i].root) t.ok(answer.intermediates[i].root);
          if (site.intermediates[i].replacement)
            t.equal(answer.intermediates[i].replacement, site.intermediates[i].replacement);
        }
      }

      t.equal(answer.diagnosis, site.diagnosis, "Wrong diagnosis: " + answer.diagnosis);

      t.end();
    });
  });
});