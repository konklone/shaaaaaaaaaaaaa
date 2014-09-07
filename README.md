## SHAAAAAAAAAAAAA

This repository contains the code for:

> **[shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com)**

You can also use the `./bin/shaaaaaaaaaaaaa` script to get an answer on the command line, or visit the excellent [SSL Labs](https://www.ssllabs.com/ssltest/analyze.html) for a far more comprehensive review of your SSL configuration.

Depends on `openssl` to do the cert download and verification.

### How do I update to SHA-2?

Read the [instructions on shaaaaaaaaaaaaa.com](https://shaaaaaaaaaaaaa.com#sha2-certificate) for replacing your cert and any intermediates.

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
