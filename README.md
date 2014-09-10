## SHAAAAAAAAAAAAA

This repository contains the code for **[shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com)**, a tool to check whether your site's certificate is signed using **SHA-1** (common, bad) or **SHA-2** (rare, good).

Read [more about why I built this tool](https://konklone.com/post/why-google-is-hurrying-the-web-to-kill-sha-1), and why replacing SHA-1 is important.

This tool does *not* validate certificates, or test anything besides SHA-1 vs SHA-2. For that, please visit the magnificent [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html) for a far more comprehensive review of your SSL configuration.

Depends on `openssl` to download certificates. See below for a [command line version](#command-line-version).

### How do I update to SHA-2?

Read the [instructions on shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com#sha2-certificate) for replacing your cert and any intermediates.

### How can I help?

Check out the [issue tracker](https://github.com/konklone/shaaaaaaaaaaaaa/issues). The biggest things are:

* How about a bookmarklet, a Firefox extension, or a Chrome extension?
* Some [annoying domain errors](https://github.com/konklone/shaaaaaaaaaaaaa/issues/34) on edge cases in Google's DNS.
* Mapping out [common certificate issuers](https://github.com/konklone/shaaaaaaaaaaaaa/issues/31) so we can easily link people to replacements.
* Hunting down [more SHA-2 intermediate locations](https://github.com/konklone/shaaaaaaaaaaaaa/issues/36) than we [currently have](https://shaaaaaaaaaaaaa.com/#sha2-intermediate) on the site.
* More [unit tests](https://github.com/konklone/shaaaaaaaaaaaaa/blob/master/test/shaaaaa.js), especially for intermediate certificates and chained root certificates.
* Getting [some Internet SHA-1 stats](https://github.com/konklone/shaaaaaaaaaaaaa/issues/16) by running the [command line tool](#command-line-version) over a list of top sites, like Alexa's [[CSV download](https://s3.amazonaws.com/alexa-static/top-1m.csv.zip)].

Really, just making the site better all around.

### Running the website

This app requires [Node](http://nodejs.org). Then, install dependencies:

```bash
npm install
```

And run the app:

```
node app.js
```

For best results, make sure your system is using the latest version of `openssl`.

### Command line version

To check a domain's certificate on the command line, use this repository's command line tool:

```bash
./bin/shaaaaaaaaaaaaa isitchristmas.com
```

This will exit with code `0`, and output formatted JSON to STDOUT:

```json
{
  "domain": "isitchristmas.com",
  "cert": {
    "algorithm": "sha1",
    "raw": "sha1WithRSAEncryption",
    "good": false,
    "expires": "2016-04-08T11:47:28.000Z",
    "name": "www.isitchristmas.com"
  },
  "intermediates": [
    {
      "algorithm": "sha256",
      "raw": "sha256WithRSAEncryption",
      "good": true,
      "expires": "2017-10-24T20:57:09.000Z",
      "name": "StartCom Class 2 Primary Intermediate Server CA"
    }
  ]
}
```

If there's an error, you'll get some JSON with an `error` flag of `true`, and the process will exit with code `1`:

```bash
$ ./bin/shaaaaaaaaaaaaa bad-domain
```

```json
{
  "error": true,
  "domain": "bad-domain",
  "message": "Couldn't lookup hostname."
}
```


## Author

This is a tiny tool by [Eric Mill](https://twitter.com/konklone). Released under an [MIT License](LICENSE).
