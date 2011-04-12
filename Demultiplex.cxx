#include <algorithm>
#include <sstream>

#include <boost/bind.hpp>

#include <asio/buffer.hpp>

#include <rutil/Logger.hxx>

#include "msrp/System.hxx"
#include "msrp/IncomingMessage.hxx"
#include "msrp/Demultiplex.hxx"
#include "msrp/OutgoingMessage.hxx"
#include "msrp/Session.hxx"
#include "msrp/Uri.hxx"

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::NONE

using namespace msrp;
using namespace std;
using namespace boost;
using namespace asio;

Demultiplex::Demultiplex() :
   mContext(mMessages.end())
{}

void
Demultiplex::insert(shared_ptr<Session> s)
{
   for (Path::const_iterator i = s->address().begin(); i != s->address().end(); ++i)
   {
      mTargets[*i] = weak_ptr<Session>(s);
   }
}

void
Demultiplex::remove(shared_ptr<Session> s)
{
   for (Path::const_iterator i = s->address().begin(); i != s->address().end(); ++i)
   {
      mTargets.erase(*i);
   }
}

void
Demultiplex::remove(const vector<Uri>& us)
{
   for (vector<Uri>::const_iterator i = us.begin(); i != us.end(); ++i)
   {
      mTargets.erase(*i);
   }
}

void
Demultiplex::insert(shared_ptr<IncomingMessage> m)
{
   mMessages[m->messageId()] = m;
}

void
Demultiplex::remove(shared_ptr<IncomingMessage> m)
{
   mMessages.erase(m->messageId());
}

void
Demultiplex::insert(boost::shared_ptr<OutgoingMessage> m)
{
   mReports[m->messageId()] = m;
}

void
Demultiplex::remove(boost::shared_ptr<OutgoingMessage> m)
{
   mReports.erase(m->messageId());
}

bool
Demultiplex::process(shared_ptr<const Message> m)
{
   // ``The receiving endpoint MUST first check the URI in the To-Path
   //   to make sure the request belongs to an existing session.  When
   //   the request is received, the To-Path will have exactly one URI,
   //   which MUST map to an existing session that is associated with
   //   the connection on which the request arrived.  If this is not
   //   true, the receiver MUST generate a 481 error and ignore the
   //   request.''
   const Path& to = m->header<ToPath>();

   if (to.empty())
   {
      return false;
   }

   TargetMap::iterator i = mTargets.find(to.front());
   if (i == mTargets.end())
   {
      ErrLog(<< "unknown target: " << to.front() << "; rejected msg");

      return false;
   }

   if (m->exists<MessageId>())
   {
      const string& id = m->header<MessageId>();

      MessageMap::iterator mi = mMessages.find(id);
      if (mi != mMessages.end())
      {
         try
         {
            shared_ptr<IncomingMessage> incoming(mi->second);

            if (incoming->process(m))
            {
               return true;
            }
         }
         catch (const bad_weak_ptr&)
         {
            WarningLog(<< "message session " << id << " defunct");

            mMessages.erase(mi);
         }
      }
      else if (m->method() == Message::REPORT)
      {
         ReportMap::iterator ri = mReports.find(id);
         if (ri != mReports.end())
         {
            try
            {
               shared_ptr<OutgoingMessage> outgoing(ri->second);

               if (outgoing->process(m))
               {
                  return true;
               }
            }
            catch (const bad_weak_ptr&)
            {
               WarningLog(<< "outgoing message " << id << " defunct, report dropped");

               mReports.erase(ri);
            }
         }
      }
   }
   else
   {
      if (m->method() == Message::SEND)
      {
         ErrLog(<< "SEND request lacks Message-Id; rejected msg");

         return false;
      }
   }

   if (!m->exists<ToPath>() || m->header<ToPath>().empty())
   {
      ErrLog(<< "message contains no To-Path; rejected msg");

      return false;
   }

   try
   {
      shared_ptr<Session> session(i->second);
      shared_ptr<IncomingMessage> incoming = session->process(m);

      if (incoming)
      {
         insert(incoming);

         mContext = mMessages.find(incoming->messageId());
      }
   }
   catch (const bad_weak_ptr&)
   {
      WarningLog(<< "session defunct: " << i->first << "; rejected msg");

      return false;
   }

   return true;
}

bool
Demultiplex::process(const const_buffer& buffer, const Message::MsgStatus status)
{
   if (mContext == mMessages.end())
   {
      return false;
   }

   bool erase = false;

   try
   {
      shared_ptr<IncomingMessage> i(mContext->second);

      if (buffer_size(buffer) == 0 || i->process(buffer))
      {
         if (status == Message::Continued)
         {
            i->continued();
         }
         else if (status == Message::Complete)
         {
            i->completed();

            erase = true;
         }
         else if (status == Message::Interrupted)
         {
            i->interrupt();

            erase = true;
         }
      }
      else
      {
         return false;
      }
   }
   catch (const bad_weak_ptr&)
   {
      erase = true;
   }

   if (erase)
   {
      mMessages.erase(mContext);

      mContext = mMessages.end();
   }

   return true;
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
