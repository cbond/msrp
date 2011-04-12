#ifndef MSRP_DNSSERVICE_HXX
#define MSRP_DNSSERVICE_HXX

#include <cassert>
#include <set>
#include <string>

#include <boost/bind.hpp>
#include <boost/checked_delete.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#include <asio.hpp>

#include <rutil/Logger.hxx>
#include <rutil/dns/DnsStub.hxx>
#include <rutil/dns/QueryTypes.hxx>

#include <resip/stack/SelectInterruptor.hxx>

#include "msrp/DnsResultHandler.hxx"
#include "msrp/CoalesceDnsResults.hxx"

namespace msrp
{

struct Query
{
   typedef resip::RR_A A;
   typedef resip::RR_SRV SRV;
   typedef resip::RR_CNAME CNAME;
   typedef resip::RR_NAPTR NAPTR;
#ifdef USE_IPV6
   typedef resip::RR_AAAA AAAA;
#endif
};

// !cb! DnsService is an adaptor that makes asio::io_service work with the
// resip event processing model.  If there are active queries, a new thread
// is spawned that does resip::DnsStub processing and posts results back to
// io_service so that the handler can be executed in the correct context.
// asio::io_service::work indicates to io_service that there is work pending.
// Handler instances must be stored so that they can be garbage collected if
// DnsService is destroyed before the query completes.

class DnsService : public asio::io_service::service
{
   public:
      DnsService(asio::io_service& ios) :
         asio::io_service::service(ios), mStop(false)
      {}

      ~DnsService()
      {
         if (mThread)
         {
            stop();
         }

         std::for_each(mHandlers.begin(), mHandlers.end(),
            boost::checked_deleter<resip::DnsResultSink>());
      }

      virtual void shutdown_service()
      {}

      template<
         typename Query,
         typename Handler
         >
      void query(const std::string& name, Handler handler)
      {
         GenericLog(resip::Subsystem::DNS, resip::Log::Info, << "DNS lookup " << name);

         {
            boost::mutex::scoped_lock lock(mMutex);

            std::auto_ptr<resip::DnsResultSink> event(
               new DnsResultHandler<Query, Handler, FreeHandler>(owner(),
                  handler,
                  FreeHandler(mHandlers)));

            mHandlers.insert(event.get());

            mStub.lookup<Query>(resip::Data::from(name), event.release());
         }

         work();
      }

      // Look up A (IP4) and AAAA (IP6) records for one host, and coalesce results.
      // The code must have been built with USE_IPV6 if you wish to do IP6 queries,
      // otherwise this will just do an A record lookup.  The handler will be called
      // with a 'const vector<asio::ip::address>&' argument.
      template<typename Handler>
      void multiquery(const std::string& name, Handler handler)
      {
         GenericLog(resip::Subsystem::DNS, resip::Log::Info, << "DNS request: " << name);

         {
            boost::mutex::scoped_lock lock(mMutex);

            std::auto_ptr<resip::DnsResultSink> event(
               new CoalesceDnsResults<Handler, FreeHandler>(owner(),
                  handler,
                  FreeHandler(mHandlers)));

            mHandlers.insert(event.get());

            const resip::Data target(resip::Data::from(name));

#ifdef USE_IPV6
            mStub.lookup<Query::AAAA>(target, event.get());
#endif

            mStub.lookup<Query::A>(target, event.release());
         }

         work();
      }

   private:
      friend class SessionFactory;

      void work()
      {
         if (mThread.get() == 0)
         {
            {
               boost::mutex::scoped_lock lock(mMutex);

               mStop = false;

               mWork.reset(new asio::io_service::work(owner()));
            }

            assert(mThread.get() == 0);

            mThread.reset(new boost::thread(boost::bind(&DnsService::run, this)));
         }

         mInterrupt.interrupt();
      }

      void run()
      {
         GenericLog(resip::Subsystem::DNS, resip::Log::Info, << "spawn process thread");

         resip::FdSet set;

         while (!mStop)
         {
            set.reset();

            {
               boost::mutex::scoped_lock lock(mMutex);

               mInterrupt.buildFdSet(set);

               mStub.buildFdSet(set);
            }

            timeval tv;
            tv.tv_sec = 3600;
            tv.tv_usec = 0;

            set.select(tv);

            {
               boost::mutex::scoped_lock lock(mMutex);

               mInterrupt.process(set);

               mStub.process(set);
            }
         }

         GenericLog(resip::Subsystem::DNS, resip::Log::Info, << "join process thread");
      }

      void stop()
      {
         if (mThread)
         {
            {
               boost::mutex::scoped_lock lock(mMutex);

               mStop = true;

               mInterrupt.interrupt();
            }

            mThread->join();
            mThread.reset();
         }

         mWork.reset();
      }

      typedef std::set<resip::DnsResultSink*> Handlers;

      class FreeHandler : public std::unary_function<Handlers::value_type, void>
      {
         public:
            FreeHandler(Handlers& h) :
               mSet(h)
            {}

            void operator()(Handlers::value_type p) const
            {
               mSet.erase(p);

               boost::checked_delete(p);
            }

         private:
            Handlers& mSet;
      };

      mutable boost::mutex mMutex;

      resip::DnsStub mStub;
      resip::SelectInterruptor mInterrupt;

      boost::scoped_ptr<boost::thread> mThread;
      boost::scoped_ptr<asio::io_service::work> mWork;

      Handlers mHandlers;

      bool mStop;
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
