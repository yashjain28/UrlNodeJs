function TestUrlNodeJs(req, resp) {
  var url = UrlNodeJs();
  var parsedUrlObj = url.parse("http://user:pass@host.com:8080/p/a/t/h?query=string#hash");
  // output: {"protocol":"http:","slashes":true,"auth":"user:pass","host":"host.com:8080","port":"8080","hostname":"host.com","hash":"#hash","search":"?query=string","query":"query=string","pathname":"/p/a/t/h","path":"/p/a/t/h?query=string","href":"http://user:pass@host.com:8080/p/a/t/h?query=string#hash"} 
  log(parsedUrlObj);
  resp.success('Success');
}
