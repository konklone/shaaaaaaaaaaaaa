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
  // need to replace this soon
  // {
  //   name: "SHA-2 with bad IM, twitter.com",
  //   domain: "twitter.com",
  //   diagnosis: "almost",

  //   cert: {good: true, algorithm: "sha256"},
  //   intermediates: [
  //     {good: false, algorithm: "sha1"}
  //   ]
  // },
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
    diagnosis: "bad",

    cert: {good: false, algorithm: "sha1"},
    intermediates: [
      {good: false, algorithm: "sha1"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Domain with number, individual8.com",
    domain: "individual8.com",

    diagnosis: "almost",
    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Domain with port, google.com:443",
    domain: "google.com:443",

    diagnosis: "bad",
    cert: {good: false, algorithm: "sha1"},
    intermediates: [
      {good: false, algorithm: "sha1"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Domain with number and port, individual8.com:443",
    domain: "individual8.com:443",

    diagnosis: "almost",
    cert: {good: true, algorithm: "sha256"},
    intermediates: [
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Internationalized Domain, domaintest.みんな",
    domain: "domaintest.xn--q9jyb4c",
    diagnosis: "bad",

    cert: {good: false, algorithm: "sha1"},
    intermediates: [
      {good: false, algorithm: "sha1"},
      {good: false, algorithm: "sha1"}
    ]
  },
  {
    name: "Internationalized Domain, اختبارنطاق.شبكة",
    domain: "xn--mgbaacjxy2c4fqb.xn--ngbc5azd",
    diagnosis: "bad",

    cert: {good: false, algorithm: "sha1"},
    intermediates: [
      {good: false, algorithm: "sha1"},
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
  },
  {
    name: "SHA-1 intermediate with known replacement, penflip.com",
    domain: "penflip.com",
    diagnosis: "bad",

    cert: {good: false, algorithm: "sha1"},
    intermediates: [
      {good: false, algorithm: "sha1", replacement: "https://www.startssl.com/certs/class1/sha2/pem/sub.class1.server.sha2.ca.pem"}
    ]
  }
];

sites.forEach(function(site) {
  test(site.name, function(t) {
    shaaaaa.from(site.domain, function(err, answer) {
      if (err) t.fail("Error checking domain: " + err);

      t.equal(site.domain, answer.domain, "Domain mismatch.");

      t.equal(site.cert.algorithm, answer.cert.algorithm, "Wrong client algorithm.");
      t.equal(site.cert.good, answer.cert.good, "Wrong client diagnosis.");

      if (site.cert.root) t.ok(answer.cert.root);

      if (site.intermediates) {
        for (var i=0; i<answer.intermediates.length; i++) {
          t.equal(site.intermediates[i].good, answer.intermediates[i].good, "Intermediate " + i + ": wrong diagnosis.")
          t.equal(site.intermediates[i].algorithm, answer.intermediates[i].algorithm, "Intermediate " + i + ": wrong algorithm.")

          if (site.intermediates[i].root) t.ok(answer.intermediates[i].root);
          if (site.intermediates[i].replacement)
            t.equal(site.intermediates[i].replacement, answer.intermediates[i].replacement);
        }
      }

      t.equal(site.diagnosis, answer.diagnosis, "Wrong diagnosis: " + answer.diagnosis);

      t.end();
    });
  });
});