var shaaa = require("./shaaa");

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

    // TODO!! Sanitize domain param in the library
    shaaa.from(domain, function(err, algorithm) {
      if (err) res.send(500, {error: err});
      else res.send({algorithm: algorithm});
    })

  });

};