#include <rutil/Inserter.hxx>
#include <rutil/Logger.hxx>

#include "msrp/System.hxx"
#include "msrp/Connection.hxx"
#include "msrp/DnsService.hxx"
#include "msrp/Session.hxx"
#include "msrp/SessionFactory.hxx"

using namespace msrp;
using namespace std;
using namespace boost;
using namespace asio;
using namespace asio::ip;
using namespace resip;

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::TRANSPORT

SessionFactory::SessionFactory(io_service& s) :
   mService(s), mPool(new ConnectionPool(s)), mDns(s)
{}

SessionFactory::~SessionFactory()
{}

io_service&
SessionFactory::service()
{
   ScopedLock lock(mMutex);

   return mService;
}

//ConnectionPool&
//SessionFactory::connections()
//{
//   ScopedLock lock(mMutex);
//
//   return *mPool;
//}

shared_ptr<Session>
SessionFactory::answer(const ip::tcp::endpoint& target, const Uri& self)
{
   ScopedLock lock(mMutex);

   shared_ptr<Connection> connection = mPool->find(target);
   if (connection)
   {
      return Session::factory(connection, self);
   }

   vector<ip::tcp::endpoint> endpoints;
   endpoints.push_back(target);

   connection = Connection::createAnswer(mService, endpoints, shared_ptr<ssl::context>());

   mPool->add(connection);

   return Session::factory(connection, self);
}

shared_ptr<Session>
SessionFactory::answer(const Uri& peer, const Uri& self, Callback handler)
{
   ScopedLock lock(mMutex);

   try
   {
      const ip::tcp::endpoint target = peer.endpoint();

      shared_ptr<Connection> c = mPool->find(target);

      if (c)
      {
         return Session::factory(c, self);
      }
      else
      {
         return answer(target, self);
      }
   }
   catch (const asio::error&)
   {}

   // relay lookup or explicit port
   assert(peer.tls() || peer.port() != 0);

   RequestInfo ri;
   ri.peer = peer;
   ri.self = self;
   ri.handler = handler;

   if (peer.port() == 0)
   {
      mDns.query<Query::SRV>(peer.host(),
            bind(&SessionFactory::onSrvResult, this, ri, _1));
   }
   else
   {
      mDns.multiquery(peer.host(),
            bind(&SessionFactory::onDnsResult, this, ri, _1));
   }

   return shared_ptr<Session>();
}

shared_ptr<Session>
SessionFactory::offer(const ip::tcp::endpoint& bind, const Uri& self)
{
   ScopedLock lock(mMutex);

   shared_ptr<Connection> connection(Connection::createOffer(mService, bind, shared_ptr<ssl::context>()));

   mPool->add(connection);

   return Session::factory(connection, self);
}

void
SessionFactory::onSrvResult(const RequestInfo, const DNSResult<DnsSrvRecord>&)
{
   // !cb! use msrp::TargetSelector to select a targets, perform DNS
   // queries on all targets, and add all the resulting endpoints to
   // the Connection target list.

   std::abort();
}

const vector<tcp::endpoint>
makeEndpoints(const vector<ip::address>& addrs, unsigned short port)
{
   vector<tcp::endpoint> r;

   for (vector<ip::address>::const_iterator i = addrs.begin(); i != addrs.end(); ++i)
   {
      r.push_back(tcp::endpoint(*i, port));
   }

   return r;
}

void
SessionFactory::onDnsResult(const RequestInfo request, const vector<ip::address>& addrs)
{
   ScopedLock lock(mMutex);

   const vector<tcp::endpoint> endpoints = makeEndpoints(addrs, request.peer.port());

   if (endpoints.empty())
   {
      // DNS error
      request.handler(shared_ptr<Session>(), asio::error::host_not_found);

      return;
   }

   for (vector<tcp::endpoint>::const_iterator i = endpoints.begin(); i != endpoints.end(); ++i)
   {
      shared_ptr<Connection> c = mPool->find(*i);
      if (c)
      {
         // ?cb? almost certainly not correct behaviour?  One of the endpoints returned
         // in the DNS query matches an existing connection, so we add the remaining
         // DNS records as reconnect hints in case this connection is dropped.  Undesirable
         // behaviour for the original owner of the connection, but desirable for the newly-
         // created Session.
         c->pushTargets(endpoints);

         request.handler(Session::factory(c, request.self), asio::error());

         return;
      }
   }

   try
   {
      shared_ptr<Connection> connection(Connection::createAnswer(mService, endpoints,
         shared_ptr<ssl::context>()));

      mPool->add(connection);

      request.handler(Session::factory(connection, request.self), asio::error());
   }
   catch (const Connection::Exception& e)
   {
      ErrLog(<< "onDnsResult: Connection::Exception caught: " << e);

      request.handler(shared_ptr<Session>(), asio::error::connection_aborted);
   }
}

void
SessionFactory::shutdown()
{
   ScopedLock lock(mMutex);

   mDns.stop();

   mPool->close();
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
