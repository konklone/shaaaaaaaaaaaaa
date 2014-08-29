var shaaaaa = require("./shaaaaa");

module.exports = function(app) {

  app.get('/', function(req, res) {
    res.render("index.html", {domain: null});
  });

  app.get('/check/:domain', function(req, res) {
    // TODO: sanitize domain for JS
    var domain = req.params.domain;

    res.render("index.html", {domain: domain});
  });

  app.get('/api/check/:domain', function(req, res) {
    var domain = req.params.domain;
    if (!domain) return res.status(500);

    // domain gets strictly sanitized in the lib, but can do
    // some stuff here too

    var escaped = domain.replace(/^https?:\/\//i, '');

    console.log("Checking domain: " + domain + ", " + escaped);

    shaaaaa.from(domain, function(err, algorithm, good) {
      if (err) return res.status(400).send({error: err});

      res.send({algorithm: algorithm, good: good, domain: escaped});
    })

  });

};