var shaaa = require("./shaaa");

module.exports = function(app) {

  app.get('/', function(req, res) {
    res.send("Hello world!");
  });

  app.get('/check/:domain', function(req, res) {
    var domain = req.params.domain;

    // TODO!! Sanitize domain param in the library
    shaaa.from(domain, function(err, algorithm) {
      res.send("Detected: " + algorithm + "\n\n");
    })

  });

};