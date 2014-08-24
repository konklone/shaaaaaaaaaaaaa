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
    shaaa.from(domain, function(err, algorithm, good) {
      if (err) return res.status(400).send({error: err});

      res.send({algorithm: algorithm, good: good});
    })

  });

};