// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// For information and guides see:
// https://ericssourcecode.github.io/




#pragma once



#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"

https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Response_fields


// HTTP/1.1
// RFC 9110

//  HTTP-message   = start-line CRLF
//                   *( field-line CRLF )
//                   CRLF
//                   [ message-body ]

// GET / HTTP/1.1
// Host: www.example.org
// User-Agent: Mozilla/5.0
// Connection: keep-alive

// GET /pub/WWW/TheProject.html HTTP/1.1
// Host: www.example.org

Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

// Transfer-Encoding: gzip, chunked

//  Content-Length := length



HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 155
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
  <head>
    <title>An Example Page</title>
  </head>
  <body>
    <p>Hello World, this is a very simple HTML document.</p>
  </body>
</html
