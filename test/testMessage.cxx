#include <cassert>
#include <iostream>
#include <sstream>

#include <boost/timer.hpp>

#include "msrp/Message.hxx"
#include "msrp/Uri.hxx"

using namespace msrp;
using namespace std;

int
main(int argc, char** argv)
{
   Message msg;
   msg.method() = Message::AUTH;
   msg.header("To-Path") = "msrp:127.0.0.1";
   msg.header("From-Path") = "msrps://relay.example.com/sessionId msrp:192.168.0.1";
   msg.header("Content-Type") = "text/plain;boundary=outer";
   msg.header("Byte-Range") = "0-65535/*";
   msg.header("Content-Length") = "65535";
   msg.header("Success-Report") = "yes";
   msg.header("Failure-Report") = "partial";
   msg.header("Extension-Header") = "beer";
   msg.header("Status") = "000 404 OK BYE";
   msg.header("Content-Disposition") =
      "render; filename=img.png; "
      "modification-date=\"Wed, 12 Feb 2005 22:05:10 -0800\"";
   msg.header("WWW-Authenticate") =
      "Digest "
      "realm=\"intra.example.com\", "
      "qop=\"auth,token\", "
      "nc=00ff0001, "
      "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";

   msg.prepare();

   const Message& pmsg(msg);

   assert(pmsg.method() == Message::AUTH);

   assert(pmsg.header<ToPath>().size() == 1);
   assert(pmsg.header<ToPath>()[0].host() == "127.0.0.1");

   assert(pmsg.header<FromPath>().size() == 2);
   assert(pmsg.header<FromPath>()[0].scheme() == "msrps");
   assert(pmsg.header<FromPath>()[0].host() == "relay.example.com");
   assert(pmsg.header<FromPath>()[0].session() == "sessionId");

   assert(pmsg.header<FromPath>()[1].scheme() == "msrp");
   assert(pmsg.header<FromPath>()[1].host() == "192.168.0.1");

   assert(pmsg.header<ContentType>().type() == "text");
   assert(pmsg.header<ContentType>().subtype() == "plain");

   assert(pmsg.header<ByteRange>().start == 0);
   assert(pmsg.header<ByteRange>().end == 65535);
   assert(pmsg.header<ByteRange>().total == ByteRange::Unknown);

   assert(pmsg.header<ContentLength>() == 65535);

   assert(pmsg.header<SuccessReport>() == true);

   assert(pmsg.header<FailureReport>() == FailureReport::Partial);

   assert(pmsg.header("Extension-Header") == "beer");

#ifdef ENABLE_AUTHTUPLE
   assert(pmsg.header<WWWAuthenticate>().scheme() == "Digest");
   assert(pmsg.header<WWWAuthenticate>().param<qop>().size() == 2);
   assert(pmsg.header<WWWAuthenticate>().param<qop>()[0] == "auth");
   assert(pmsg.header<WWWAuthenticate>().param<qop>()[1] == "token");
   assert(pmsg.header<WWWAuthenticate>().param<realm>() == "intra.example.com");
   assert(pmsg.header<WWWAuthenticate>().param<nonce>() == "dcd98b7102dd2f0e8b11d0f600bfb0c093");
#endif

   cout << pmsg << endl;

   return 0;
}
