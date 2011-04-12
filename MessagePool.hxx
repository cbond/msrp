#ifndef MSRP_MESSAGEPOOL_HXX
#define MSRP_MESSAGEPOOL_HXX

#include <boost/pool/object_pool.hpp>

#include <boost/shared_ptr.hpp>

namespace msrp
{

class Message;

// Use MessagePool to decrease heap fragmentation, speed message allocation,
// and decrease the working set size in applications that allocate a lot of
// messages concurrently.  Note: It is very important that Message objects
// allocated by MessagePool not outlive the pool itself, or the destructor
// will crash.  A check should be probably be added and an exception thrown
// in this case (in debug mode).

class MessagePool
{
   public:
      static MessagePool& instance()
      {
         return Instance;
      }

      class Destructor
      {
         public:
            Destructor(boost::object_pool<Message>& pool) :
               mPool(pool)
            {}

            void operator()(Message* m)
            {
               mPool.destroy(m);
            }

         private:
            boost::object_pool<Message>& mPool;
      };

      inline boost::shared_ptr<Message> allocate()
      {
         boost::shared_ptr<Message> msg(mPool.construct(), Destructor(mPool));

         if (msg.get() == 0)
         {
            throw std::bad_alloc();
         }

         return msg;
      }

   private:
      boost::object_pool<Message> mPool;

      static MessagePool Instance;
};

}

#endif

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
