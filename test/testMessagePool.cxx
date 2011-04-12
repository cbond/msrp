#include <cassert>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>

#include <boost/bind.hpp>
#include <boost/thread.hpp>

#include "msrp/Message.hxx"
#include "msrp/MessagePool.hxx"

using namespace boost;
using namespace msrp;
using namespace std;

// !cb! Primarily serves as a performance test for Message instantiation
// via msrp::MessagePool.  Memory usage should remain almost static and
// the test (>100,000 concurrent allocations) should not take very long.

class PoolAllocatorThread
{
   public:
      PoolAllocatorThread(MessagePool& pool)
         : mPool(pool), mRemaining(1024 * 8)
      {
         mMessages.reserve(mRemaining);
      }

      void run()
      {
         size_t alloc = 0;
         size_t freed = 0;

         size_t msgs = 0;

         while (mRemaining)
         {
            if (mMessages.empty() || (random() % 3) != 0)
            {
               mMessages.push_back(mPool.allocate());

               --mRemaining;

               ++alloc;
            }
            else
            {
               vector<shared_ptr<Message> >::iterator i = mMessages.begin();
               advance(i, random() % mMessages.size());

               mMessages.erase(i);

               ++freed;
            }

            if ((++msgs % 1000) == 0)
            {
               cerr << this << ": "
                    << alloc << " alloc "
                    << freed << " freed"
                    << endl;
            }
         }

         mMessages.clear();
      }

   private:
      MessagePool& mPool;

      vector<shared_ptr<Message> > mMessages;

      size_t mRemaining;
};

int
main(int argc, char** argv)
{
   srandom(time(0));

   MessagePool pool;

   PoolAllocatorThread allocator1(pool);
   thread t1(bind(&PoolAllocatorThread::run, &allocator1));

   PoolAllocatorThread allocator2(pool);
   thread t2(bind(&PoolAllocatorThread::run, &allocator2));

   t1.join();

   t2.join();

   return 0;
}
