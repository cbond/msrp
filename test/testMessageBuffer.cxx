#include <cassert>
#include <iostream>
#include <sstream>

#include <boost/algorithm/string.hpp>

#include <rutil/Logger.hxx>
#include <rutil/DataStream.hxx>

#include "msrp/MessageBuffer.hxx"

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::TEST

using namespace msrp;
using namespace std;
using namespace resip;

void
test(const string& msg)
{
   Data data(msg.c_str(), msg.size());

   MessageBuffer buffer(data.size());
   memcpy(asio::buffer_cast<char*>(buffer.mutableBuffer()), data.data(), data.size());

   buffer.read(data.size());
   assert(buffer.state() == MessageBuffer::Complete);

   boost::shared_ptr<Message> parsed = buffer.parse(MessageBuffer::CopyContents);

   stringstream encoded;
   encoded << *parsed;

   assert(data.md5() == Data(encoded.str()).md5());
}

int
main(int argc, char** argv)
{
   const string eol("\r\n");

   Log::initialize(Log::Cout, Log::Debug, argv[0]);

   stringstream msg;

   msg
      << "MSRP 49fh AUTH" << eol
      << "To-Path: msrps://alice@intra.example.com;tcp" << eol
      << "From-Path: msrps://alice.example.com:9892/98cjs;tcp" << eol
      << "-------49fh$";
   test(msg.str());
   msg.str(string());

   msg
      << "MSRP d93kswow SEND" << eol
      << "To-Path: msrp://bob.example.com:8888/9di4ea;tcp" << eol
      << "From-Path: msrp://alicepc.example.com:7777/iau39;tcp" << eol
      << "Content-Type: text/plain" << eol
      << "Message-ID: 12339sdqwer" << eol
      << eol
      << "Hi, I'm Alice!" << eol
      << "-------d93kswow$";
   test(msg.str());
   msg.str(string());

   msg
      << "MSRP d93kswow SEND" << eol
      << "To-Path: msrp://alicepc.example.com:8888/9di4ea;tcp" << eol
      << "From-Path: msrp://example.com:7777/iau39;tcp" << eol
      << "Content-Type: text/plain" << eol
      << "Failure-Report: no" << eol
      << "Message-ID: 12339sdqwer" << eol
      << "Success-Report: no" << eol
      << eol
      << "This conference will end in 5 minutes"
      << "-------d93kswow$";
   test(msg.str());

   // test partial reads

   const string mstr = msg.str();

   MessageBuffer partial;

   memcpy(asio::buffer_cast<char*>(partial.mutableBuffer()), mstr.c_str(), mstr.size());

   size_t roff = mstr.find("To-Path");

   partial.read(roff);
   assert(partial.state() == MessageBuffer::Headers);

   size_t next = mstr.find("Message-ID");

   partial.read(next - roff);
   assert(partial.state() == MessageBuffer::Headers);

   roff = next;
   next = mstr.find("\r\n\r\n") + 4;

   partial.read(next - roff);
   assert(partial.state() == MessageBuffer::Content);

   roff = next;
   next = mstr.find("$") + 1;

   partial.read(next - roff);
   assert(partial.state() == MessageBuffer::Complete);

   return 0;
}
