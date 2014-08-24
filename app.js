// this is an Express app
var express = require('express');
var app = express();

// environment and port
var env = process.env.NODE_ENV || 'development';
var port = parseInt(process.argv[2], 10);
if (isNaN(port)) port = 3000;

// app middleware/settings
app.engine('.html', require('ejs').__express);
app.enable('trust proxy')
  .use(require('body-parser').json())
  .use(require('body-parser').urlencoded({extended: false}))
  .use(require('method-override')())
  .use(function(req,res,next){
    res.locals.req = req;
    next();
  })
  .use(express.static(__dirname + '/public'));

// development vs production
if (env == "development")
  app.use(require('errorhandler')({dumpExceptions: true, showStack: true}))
else
  app.use(require('errorhandler')())

/* actual app */

var exec = require("child_process").exec;

app.get('/', function(req, res) {
  res.send("Hello world!");
});

app.get('/check/:domain', function(req, res) {
  var domain = req.params.domain;

  // TODO!! Sanitize domain param

  cmd = "" +
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

  // output will look like:
  // '    Signature Algorithm: sha256WithRSAEncryption\n    Signature Algorithm: sha256WithRSAEncryption\n'

  exec(cmd, function(error, stdout, stderr) {
    var line = stdout.split("\n")[0].trim();
    var pieces = line.split(" ");
    var raw = pieces[pieces.length - 1];
    var algorithm;
    if (raw.indexOf("sha256") == 0) {
      algorithm = "sha256";
    } else if (raw.indexOf("sha1") == 0) {
      algorithm = "sha1";
    } else {
      algorithm = "unknown";
    }

    res.send("Detected: " + algorithm + "\n\n" + raw);
  });

});


// boot it up!
app.listen(port, function() {
  console.log("Express server listening on port %s in %s mode", port, env);
});
