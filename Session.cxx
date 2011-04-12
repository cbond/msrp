#include <sstream>

#include <rutil/Logger.hxx>

#include "msrp/System.hxx"
#include "msrp/Connection.hxx"
#include "msrp/IncomingMessage.hxx"
#include "msrp/OutgoingMessage.hxx"
#include "msrp/Session.hxx"

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::TRANSPORT

using namespace msrp;
using namespace boost;
using namespace std;
using namespace asio;
using namespace asio::ip;

shared_ptr<Session>
Session::factory(shared_ptr<Connection> connection, const Uri& self)
{
   shared_ptr<Session> s(new Session(connection, self));
   if (s)
   {
      connection->demultiplexer().insert(s);
   }

   return s;
}

Session::Session(shared_ptr<Connection> connection, const Uri& self) :
   mConnection(connection)
{
   assert(mConnection);

   mConnection->dependents()++;

   if (self.empty())
   {
      mPath.push_back(Uri(mConnection->local(), mConnection->tls()));
   }
   else
   {
      mPath.push_back(self);
   }
}

Session::~Session()
{
   if (mConnection)
   {
      StreamContext& context = mConnection->context();
      context.clear();

      mConnection->demultiplexer().remove(address());

      // !cb! hack
      if (--mConnection->dependents() == 0)
      {
         mConnection->close();
      }
   }
}

const Path&
Session::address() const
{
   ScopedLock lock(mMutex);

   return mPath;
}

shared_ptr<Connection>
Session::connection() const
{
   ScopedLock lock(mMutex);

   return mConnection;
}

shared_ptr<IncomingMessage>
Session::process(shared_ptr<const Message> m)
{
   ScopedLock lock(mMutex);

   if (m->status() == Message::Complete)
   {
      if (!mMessage.empty())
      {
         mMessage(m);
      }
      else
      {
         WarningLog(<< "no single message handler; dropped");

         return shared_ptr<IncomingMessage>();
      }
   }

   if (mSession.empty())
   {
      WarningLog(<< "no message session handler; message dropped");
   }
   else
   {
      shared_ptr<IncomingMessage> ms(new IncomingMessage(shared_from_this(), *m));

      // !cb! Query the session and ask it to handle this new message session.
      // It can choose to accept or reject it.  If it accepts, we return the
      // session to Demultiplex and add it to the in-routes.
      if (mSession(ms))
      {
         mIncoming.push_back(ms);

         // remove the session from mIncoming when complete
         ms->onComplete().connect(bind(&Session::onIncomingComplete, this, ms->messageId()));

         return ms;
      }
   }

   return shared_ptr<IncomingMessage>();
}

bool
Session::prepare(Message& m) const
{
   ScopedLock lock(mMutex);

   bool modified = m.prepare();

   if (!m.exists<FromPath>())
   {
      m.header<FromPath>().push_back(address().front());

      modified = true;
   }

   if (!m.exists<ToPath>())
   {
      m.header<ToPath>().push_back(Uri(mConnection->peer(), mConnection->tls()));

      modified = true;
   }

   return modified;
}

shared_ptr<OutgoingMessage>
Session::stream(const Message& m)
{
   ScopedLock lock(mMutex);

   if (!connection())
   {
      throw Exception("session not connected", codeContext());
   }

   shared_ptr<OutgoingMessage> msg(new OutgoingMessage(shared_from_this(), m));
   assert(msg);

   // remove the session from mOutgoing when complete
   msg->onComplete().connect(bind(&Session::onOutgoingComplete, this, msg->messageId()));

   shared_ptr<Connection> c(connection());

   // outgoing message scheduler
   c->scheduler().queue(msg);

   // demuxer for incoming reports
   c->demultiplexer().insert(msg);

   // Post a message to start sending after the caller has connected its
   // handlers to the OutgoingMessage event signals.  (The scheduler may
   // not select this message to send, but it will at least update its
   // internal state to take into account this message.)
   c->service().post(bind(&Connection::selectOutgoing, c));

   return msg;
}

void
Session::onIncomingComplete(const string& id)
{
   ScopedLock lock(mMutex);

   vector<shared_ptr<IncomingMessage> >::iterator i = mIncoming.begin();

   for (; i != mIncoming.end(); ++i)
   {
      if (i->get()->messageId() == id)
      {
         mIncoming.erase(i);
         break;
      }
   }
}

void
Session::onOutgoingComplete(const string& id)
{
   ScopedLock lock(mMutex);

   vector<shared_ptr<OutgoingMessage> >::iterator i = mOutgoing.begin();

   for (; i != mOutgoing.end(); ++i)
   {
      if (i->get()->messageId() == id)
      {
         shared_ptr<Connection> c(connection());
         if (c)
         {
            // outgoing message scheduler
            c->scheduler().erase(*i);

            // !cb! Incoming report demuxer.  This is not correct.  We should
            // store whether or not we expect reports back from the peer, and
            // not remove the OutgoingMessage until we have received the final
            // report if so.
            c->demultiplexer().remove(*i);
         }

         mOutgoing.erase(i);

         break;
      }
   }
}

signal1<void, shared_ptr<const Message> >&
Session::onMessage()
{
   ScopedLock lock(mMutex);

   return mMessage;
}

signal1<bool, shared_ptr<IncomingMessage> >&
Session::onMessageSession()
{
   ScopedLock lock(mMutex);

   return mSession;
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
