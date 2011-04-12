#include <sstream>

#include <rutil/Logger.hxx>

#include "msrp/System.hxx"
#include "msrp/Message.hxx"
#include "msrp/OutgoingMessage.hxx"
#include "msrp/Session.hxx"

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::NONE

using namespace msrp;
using namespace std;
using namespace boost;
using namespace asio;

OutgoingMessage::OutgoingMessage(shared_ptr<Session> s, const Message& m) :
   MessageSessionBase(m), mSession(s)
{}

OutgoingMessage::~OutgoingMessage()
{}

void
OutgoingMessage::cancel()
{
   ScopedLock lock(mMutex);

   mInterrupted = true;
}

signal1<void, const Message&>&
OutgoingMessage::onReport()
{
   ScopedLock lock(mMutex);

   return mReport;
}

signal1<void, Message&>&
OutgoingMessage::onContextRequired()
{
   ScopedLock lock(mMutex);

   return mContext;
}

signal2<void, size_t, OutgoingMessage::StreamFunctor&>&
OutgoingMessage::onDataRequired()
{
   ScopedLock lock(mMutex);

   return mData;
}

size_t
OutgoingMessage::queued() const
{
   ScopedLock lock(mMutex);

   return static_cast<size_t>(mQueued.size());
}

shared_ptr<Session>
OutgoingMessage::session() const
{
   ScopedLock lock(mMutex);

   return mSession.lock();
}

template<typename T>
static void
send(shared_ptr<Connection> c, const T& data)
{
   assert(c);

   c->send(data);
}

template<typename T>
static void
send(shared_ptr<Session> s, const T& data)
{
   assert(s);

   shared_ptr<Connection> c = s->connection();
   assert(c);

   ::send(c, data);
}

// process an incoming report
bool
OutgoingMessage::process(shared_ptr<const Message> m)
{
   ScopedLock lock(mMutex);

   if (!onReport().empty())
   {
      onReport()(*m);

      return true;
   }

   return false;
}

void
OutgoingMessage::start()
{
   ScopedLock lock(mMutex);

   // !cb! Take a shot at constructing a correct context message based
   // on the template in the base class, but let the application modify
   // it through the onContextRequired signal.

   Message& m = message();

   m.header<ByteRange>().start = transferred() + 1;
   m.header<ByteRange>().end = ByteRange::Unknown;

   if (!mContext.empty())
   {
      onContextRequired()(m);
   }

   stringstream stream;

   m.encodeHeader(stream);

   stream << '\r'
          << '\n';

   ::send(session(), const_buffer(stream.str().c_str(), stream.str().size()));

   mFragment = 0;
}

void
OutgoingMessage::end(shared_ptr<Connection> c)
{
   ScopedLock lock(mMutex);

   assert(c);

   Message& m = message();
   if (complete())
   {
      m.status() = Message::Complete;
   }
   else if (interrupted())
   {
      m.status() = Message::Interrupted;
   }
   else
   {
      m.status() = Message::Continued;
   }

   stringstream stream;

   m.contents().clear();
   m.encodeContents(stream);

   ::send(c, const_buffer(stream.str().c_str(), stream.str().size()));

   if (complete() || interrupted())
   {
      c->scheduler().erase(shared_from_this());

      if (!onComplete().empty())
      {
         onComplete()();
      }
   }
}

void
OutgoingMessage::end()
{
   shared_ptr<Session> s = session();
   if (s)
   {
      end(s->connection());
   }
}

bool
OutgoingMessage::runnable() const
{
   ScopedLock lock(mMutex);

   if (complete())
   {
      return false;
   }

   // !cb! The message is considered `runnable' if there is data in the send
   // queue; if there is a handler connected to the data input signal; or if
   // the message has been interrupted and this needs to be indicated to the
   // remote party.  In all of these cases, there is data that needs to be
   // sent.
   return queued() || interrupted() || !mData.empty();
}

void
OutgoingMessage::run()
{
   ScopedLock lock(mMutex);

   assert(runnable());

   shared_ptr<Session> s = session();
   assert(s);

   StreamFunctor stream(*this, s->connection());

   if (queued())
   {
      stream(mQueued);

      mQueued.clear();
   }
   else
   {
      if (!interrupted())
      {
         size_t required = 0;

         const Message& m = message();

         if (m.exists<ByteRange>() &&
             m.header<ByteRange>().end != ByteRange::Unknown)
         {
            required = m.header<ByteRange>().end - mFragment;
         }

         onDataRequired()(required, stream);
      }
   }
}

void
OutgoingMessage::send(const const_buffer& b)
{
   ScopedLock lock(mMutex);

   if (complete() || interrupted())
   {
      throw Session::Exception("message session is inactive", codeContext());
   }

   mQueued.append(buffer_cast<const char*>(b), buffer_size(b));
}

// OutgoingMessage::StreamFunctor

OutgoingMessage::StreamFunctor::StreamFunctor(OutgoingMessage& om, shared_ptr<Connection> c) :
   mOutgoing(om), mConnection(c)
{
   assert(mConnection);
}

void
OutgoingMessage::StreamFunctor::operator()(const resip::Data& data)
{
   operator()(const_buffer(data.data(), data.size()));
}

void
OutgoingMessage::StreamFunctor::operator()(const const_buffer& b)
{
   mConnection->send(b);

   ScopedLock lock(mOutgoing.mMutex);

   mOutgoing.mTransferred += buffer_size(b);

   mOutgoing.mFragment += buffer_size(b);

   mOutgoing.mLastTransfer = posix_time::microsec_clock::local_time();

   // !cb! If all data has been sent, end the outgoing message.
   if (mOutgoing.size())
   {
      assert(mOutgoing.transferred() <= mOutgoing.size());

      if (mOutgoing.transferred() == mOutgoing.size())
      {
         mOutgoing.mComplete = true;

         mConnection->context().clear();
      }
   }
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
