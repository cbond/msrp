#include <iomanip>

#include <rutil/Logger.hxx>
#include <rutil/Random.hxx>

#include "msrp/System.hxx"
#include "msrp/Parse.hxx"
#include "msrp/Message.hxx"
#include "msrp/MessagePool.hxx"
#include "msrp/ParseException.hxx"
#include "msrp/ParseMessage.hxx"
#include "msrp/ParserFactory.hxx"

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::NONE

using namespace msrp;
using namespace std;
using namespace boost;

shared_ptr<Message>
Message::factory(const asio::const_buffer& buffer)
{
   shared_ptr<Message> m = factory();

   Parse(*m, buffer, ParserFactory<parser::Message>::get());

   return m;
}

shared_ptr<Message>
Message::factory()
{
   return MessagePool::instance().allocate();
}

Message::Message() :
   mStatusCode(0),
   mMethod(SEND),
   mStatus(Complete)
{}

shared_ptr<Message>
Message::response(unsigned int code, const string& phrase) const
{
   assert(transaction().size());
   assert(exists<ToPath>());
   assert(exists<FromPath>());

   shared_ptr<Message> r = factory();
   assert(r);

   r->statusCode() = code;
   r->statusPhrase() = phrase;

   r->method() = Message::Response;
   r->status() = Message::Complete;

   r->transaction() = transaction();

   if (exists<MessageId>())
   {
      r->header<MessageId>() = header<MessageId>();
   }

   // ``If the request triggering the response was a SEND request, the To-Path
   //   header field is formed by copying the last (right-most) URI in the
   //   From-Path header field of the request.  (Responses to SEND requests
   //   are returned only to the previous hop.)  For responses to all other
   //   request methods, the To-Path header field contains the full path back
   //   to the original sender.''  -- draft 18
   if (method() == SEND)
   {
      r->header<ToPath>().push_back(header<FromPath>().back());
   }
   else
   {
      Path::const_reverse_iterator i = header<FromPath>().rbegin();

      while (i != header<FromPath>().rend())
      {
         r->header<ToPath>().push_back(*i++);
      }
   }

   r->header<FromPath>().push_back(header<ToPath>().front());

   return r;
}

ostream&
Message::encodeHeader(ostream& os) const
{
   const string crlf("\r\n");
   const string colon(": ");

   assert(!transaction().empty());

   assert(exists<ToPath>());
   assert(exists<FromPath>());

   os << "MSRP ";
   os << transaction();
   os << ' ';

   switch (method())
   {
      case Message::AUTH:
         os << "AUTH";
         break;

      case Message::SEND:
         os << "SEND";
         break;

      case Message::REPORT:
         os << "REPORT";
         break;

      case Message::Response:
         if (statusCode() < 100)
         {
            std::ios::fmtflags flags = os.flags();

            os.setf(ios_base::right);
            os << std::setw(3)
               << std::setfill('0')
               << std::dec
               << statusCode();

            os.flags(flags);
         }
         else
         {
            os << statusCode();
         }

         if (!statusPhrase().empty())
         {
            os << ' ';
            os << statusPhrase();
         }

         break;

      default:
         abort();
   }

   os << crlf;

   // To-Path
   os << ToPath::Key
      << colon
      << header<ToPath>()
      << crlf;

   // From-Path
   os << FromPath::Key
      << colon
      << header<FromPath>()
      << crlf;

   // Message-ID
   if (lazyStorage<MessageId>().parsed())
   {
      os << MessageId::Key
         << colon
         << header<MessageId>()
         << crlf;
   }

   // Success-Report
   if (lazyStorage<SuccessReport>().parsed())
   {
      os << SuccessReport::Key << colon;

      if (header<SuccessReport>())
      {
         os << "yes";
      }
      else
      {
         os << "no";
      }

      os << crlf;
   }

   // Failure-Report
   if (lazyStorage<FailureReport>().parsed())
   {
      os << FailureReport::Key << colon;

      switch (header<FailureReport>())
      {
         case FailureReport::Yes:
            os << "yes";
            break;
         case FailureReport::No:
            os << "no";
            break;
         case FailureReport::Partial:
            os << "partial";
            break;
      }

      os << crlf;
   }

   // Content-Type
   if (lazyStorage<ContentType>().parsed())
   {
      os << ContentType::Key
         << colon
         << header<ContentType>()
         << crlf;
   }

   // Content-Length
   if (lazyStorage<ContentLength>().parsed())
   {
      os << ContentLength::Key
         << colon
         << header<ContentLength>()
         << crlf;
   }

   // Byte-Range
   if (lazyStorage<ByteRange>().parsed())
   {
      os << ByteRange::Key
         << colon
         << header<ByteRange>()
         << crlf;
   }

   // Status
   if (lazyStorage<Status>().parsed())
   {
      os << msrp::Status::Key
         << colon
         << header<Status>()
         << crlf;
   }

#ifdef ENABLE_AUTHTUPLE
   // WWW-Authenticate
   if (lazyStorage<WWWAuthenticate>().parsed())
   {
      os << WWWAuthenticate::Key
         << colon
         << header<WWWAuthenticate>()
         << crlf;
   }
   // Authentication-Info
   else if (lazyStorage<AuthenticationInfo>().parsed())
   {
      os << AuthenticationInfo::Key
         << colon
         << header<AuthenticationInfo>()
         << crlf;
   }
   // Authorization
   else if (lazyStorage<Authorization>().parsed())
   {
      os << Authorization::Key
         << colon
         << header<Authorization>()
         << crlf;
   }
#endif // ENABLE_AUTHTUPLE

   // remaining unparsed headers
   for (map<string, string>::const_iterator i = mHeaders.begin(); i != mHeaders.end(); ++i)
   {
      os << i->first
         << colon
         << i->second
         << crlf;
   }

   return os;
}

void
Message::preparse()
{
   if (exists<FromPath>()) header<FromPath>();
   if (exists<ToPath>()) header<ToPath>();
   if (exists<FromPath>()) header<FromPath>();
   if (exists<ToPath>()) header<ToPath>();
   if (exists<UsePath>()) header<UsePath>();
   if (exists<MessageId>()) header<MessageId>();
   if (exists<ContentLength>()) header<ContentLength>();
   if (exists<ContentType>()) header<ContentType>();
   if (exists<ByteRange>()) header<ByteRange>();
   if (exists<Expires>()) header<Expires>();
   if (exists<MinExpires>()) header<MinExpires>();
   if (exists<Status>()) header<Status>();
   if (exists<SuccessReport>()) header<SuccessReport>();
   if (exists<FailureReport>()) header<FailureReport>();
#ifdef ENABLE_AUTHTUPLE
   if (exists<WWWAuthenticate>()) header<WWWAuthenticate>().preparse();
   if (exists<AuthenticationInfo>()) header<AuthenticationInfo>().preparse();
   if (exists<Authorization>()) header<Authorization>().preparse();
#endif
}

ostream&
Message::encodeContents(ostream& os) const
{
   if (!contents().empty())
   {
      os << "\r\n";
      os << contents();
   }

   if (status() == Message::Streaming)
   {
      return os;
   }

   os << "-------";
   os << transaction();

   switch (status())
   {
      case Message::Continued:
         os << '+';
         break;
      case Message::Complete:
         os << '$';
         break;
      case Message::Interrupted:
         os << '#';
         break;
      default:
         abort();
   }

   return os;
}

ostream&
msrp::operator<<(ostream& os, const Message& msg)
{
   msg.encodeHeader(os);
   msg.encodeContents(os);

   return os;
}

static const string
randomId()
{
   unsigned int couples = 7 + (resip::Random::getRandom() % 8);

   return resip::Random::getCryptoRandomHex(couples).c_str();
}

bool
Message::prepare()
{
   bool modified = false;

   if (!exists<MessageId>() || header<MessageId>().empty())
   {
      headerRef<MessageId>() = randomId();
      modified = true;
   }

   if (transaction().empty())
   {
      transaction() = randomId();
      modified = true;
   }

   return modified;
}

// Copyright 2007 Chris Bond
// 
// Permission is hereby granted, free of charge, to any person or organization
// obtaining a copy of the software and accompanying documentation covered by
// this license (the "Software") to use, reproduce, display, distribute,
// execute, and transmit the Software, and to prepare derivative works of the
// Software, and to permit third-parties to whom the Software is furnished to
// do so, all subject to the following:
// 
// The copyright notices in the Software and this entire statement, including
// the above license grant, this restriction and the following disclaimer,
// must be included in all copies of the Software, in whole or in part, and
// all derivative works of the Software, unless such copies or derivative
// works are solely in the form of machine-executable object code generated by
// a source language processor.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
// FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
