#include <cstdio>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <boost/scoped_ptr.hpp>

#include "msrp/System.hxx"
#include "msrp/IncomingMessage.hxx"
#include "msrp/OutgoingMessage.hxx"
#include "msrp/SessionFactory.hxx"
#include "msrp/Session.hxx"

using namespace msrp;
using namespace std;
using namespace boost;
using namespace resip;
using namespace asio;

#define RESIPROCATE_SUBSYSTEM Subsystem::TEST

class OfferSession
{
   public:
      OfferSession(SessionFactory& sf, const string& file) :
         mFactory(sf), mFile(file), mTimer(sf.service())
      {
         mFd = open(file.c_str(), O_RDONLY);
         assert(mFd >= 0);

         struct stat sb = { 0 };
         fstat(mFd, &sb);

         mSize = sb.st_size;
         mRead = 0;
      }

      void create()
      {
         ip::tcp::endpoint bound(ip::address_v4::any(), 9955);

         mSession = mFactory.offer(bound, Uri("msrp:127.0.0.1:9955"));

         InfoLog(<< "offer session created, bound to " << bound);

         assert(mSession);
         assert(mSession->connection());

         shared_ptr<Connection> c = mSession->connection();

         c->onConnect().connect(bind(&OfferSession::onAccept, this, _1));
      }

   private:
      void onAccept(const ip::tcp::endpoint& peer)
      {
         InfoLog(<< "OfferSession::onAccept: from " << peer);

         Message m;

         mSession->prepare(m);

         m.method() = Message::SEND;
         m.status() = Message::Complete;

         m.header("Filename") = "testFile";

         ByteRangeTuple& br = m.header<ByteRange>();
         br.total = mSize;

         mOutgoing = mSession->stream(m);

         mOutgoing->onDataRequired().connect(bind(&OfferSession::onData, this, _1, _2));
      }

      void onData(size_t reqd, OutgoingMessage::StreamFunctor& stream)
      {
         DebugLog(<< "onDataRequired: " << reqd);

         char readbuf[256] = { 0 };

         int r = ::read(mFd, readbuf, min<unsigned int>(mSize - mRead, 256));

         mRead += r;

         const_buffer buf((const char*)readbuf, r);

         stream(buf);
      }

      SessionFactory& mFactory;

      shared_ptr<Session> mSession;

      shared_ptr<OutgoingMessage> mOutgoing;

      const string mFile;

      unsigned int mSize;
      unsigned int mRead;

      int mFd;

      deadline_timer mTimer;
};

class AnswerSession
{
   public:
      AnswerSession(SessionFactory& sf) :
         mFactory(sf)
      {}

      void create()
      {
         mSession = mFactory.answer(
               Uri("msrp:127.0.0.1:9955"),
               Uri(),
               bind(&AnswerSession::onSession, this, _1, _2));

         if (mSession)
         {
            InfoLog(<< "answer session created, target msrp:127.0.0.1:9955");

            connectHandlers();
         }
         else
         {
            InfoLog(<< "waiting for DNS");
         }
      }

   private:
      void onSession(shared_ptr<Session> s, const asio::error& e)
      {
         if (e)
         {
            ErrLog(<< "session creation failed: " << e);
         }
         else
         {
            InfoLog(<< "answer session created, target msrp:127.0.0.1:9955");

            mSession = s;

            connectHandlers();
         }
      }

      void connectHandlers()
      {
         assert(mSession);
         assert(mSession->connection());

         mSession->onMessage().connect(bind(&AnswerSession::onMessage, this, _1));
         mSession->onMessageSession().connect(bind(&AnswerSession::onMessageSession, this, _1));

         shared_ptr<Connection> c = mSession->connection();

         c->onConnect().connect(bind(&AnswerSession::onConnect, this, _1));
      }

      void onConnect(const ip::tcp::endpoint& endpoint)
      {
         InfoLog(<< "AnswerSession: connected to " << endpoint);
      }

      void onMessage(shared_ptr<const Message> msg)
      {
         InfoLog(<< "received: " << *msg);
      }

      bool onMessageSession(shared_ptr<IncomingMessage> ims)
      {
         const Message& m = ims->message();

         mFilename = m.header("Filename");

         InfoLog(<< "incoming message session, file: " << mFilename);

         mFd = ::open(mFilename.c_str(), O_CREAT | O_TRUNC | O_APPEND | O_WRONLY, 0600);
         assert(mFd >= 0);

         ims->onContext().connect(bind(&AnswerSession::onMessageSessionContext, this, _1));
         ims->onContents().connect(bind(&AnswerSession::onMessageSessionContents, this, _1));
         ims->onComplete().connect(bind(&AnswerSession::onMessageSessionComplete, this));

         onMessageSessionContext(ims->message());

         return true;
      }

      void onMessageSessionContext(const Message& m)
      {
         InfoLog(<< "message session context: " << m);
      }

      void onMessageSessionContents(const asio::const_buffer& b)
      {
         const string contents(buffer_cast<const char*>(b), buffer_size(b));

         InfoLog(<< "message session contents: {" << contents << "}");

         ::write(mFd, contents.c_str(), contents.size());
      }

      void onMessageSessionComplete()
      {
         InfoLog(<< "transmission complete");

         ::close(mFd);
         mFd = -1;

         mFactory.shutdown();
      }

      SessionFactory& mFactory;

      shared_ptr<Session> mSession;

      string mFilename;

      int mFd;
};

int
main(int argc, char** argv)
{
   Log::initialize(Log::Cout, Log::Debug, argv[0]);

   asio::io_service fifo;

   SessionFactory sf(fifo);

   scoped_ptr<OfferSession> os(new OfferSession(sf, "testSessionFactory.cxx"));
   os->create();

   scoped_ptr<AnswerSession> as(new AnswerSession(sf));
   as->create();

   fifo.run();

   return 0;
}
