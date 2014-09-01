var shaaaaa = require("./shaaaaa");

module.exports = function(app) {

  app.get('/', function(req, res) {
    res.render("index.html", {domain: null});
  });

  app.get('/check/:domain', function(req, res) {
    res.render("index.html", {domain: req.params.domain});
  });

  app.get('/api/check/:domain', function(req, res) {
    var domain = req.params.domain;
    if (!domain) return res.status(500);

    // remove any protocol prefix
    var escaped = domain.replace(/^https?:\/\//i, '');

    console.log("Checking domain: " + domain + ", " + escaped);

    shaaaaa.from(domain, function(err, algorithm, good) {
      if (err) return res.status(400).send({error: err});

      res.send({algorithm: algorithm, good: good, domain: escaped});
    })

  });

};