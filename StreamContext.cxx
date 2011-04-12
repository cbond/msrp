#include "msrp/System.hxx"
#include "msrp/Connection.hxx"
#include "msrp/OutgoingMessage.hxx"
#include "msrp/Scheduler.hxx"
#include "msrp/Session.hxx"
#include "msrp/StreamContext.hxx"

using namespace msrp;
using namespace boost;

StreamContext::StreamContext()
{}

void
StreamContext::select(Scheduler& scheduler)
{
   shared_ptr<OutgoingMessage> m = scheduler.thread();

   if (m && m->runnable())
   {
      if (m != mCurrent)
      {
         if (mCurrent)
         {
            mCurrent->end();
         }

         mCurrent = m;
         mCurrent->start();

         shared_ptr<Session> s = mCurrent->session();
         assert(s);

         mConnection = s->connection();
      }

      mCurrent->run();
   }
   else
   {
      // !cb! If mCurrent is not null, just leave it be -- by the next time this
      // function is called, we may want to send data from the same message,
      // avoiding a context switch.
   }
}

void
StreamContext::clear()
{
   if (mCurrent)
   {
      shared_ptr<Connection> c = mConnection.lock();
      assert(c);

      mCurrent->end(c);
      mCurrent.reset();
   }

   mConnection.reset();
}

StreamContext::~StreamContext()
{
   clear();
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