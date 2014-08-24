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

app.locals.helpers = {
  escape_attribute: function(text) {
    return text.replace(/\"/g, "&quot;");
  }
};
var routes = require("./routes")(app);

// boot it up!
app.listen(port, function() {
  console.log("Express server listening on port %s in %s mode", port, env);
});
