#include <cassert>
#include <functional>
#include <string>

#include <boost/bind.hpp>

#include <asio/deadline_timer.hpp>

#include <rutil/Logger.hxx>
#include <rutil/DnsUtil.hxx>
#include <rutil/dns/DnsStub.hxx>

#include "msrp/DnsService.hxx"
#include "msrp/TargetSelector.hxx"

using namespace msrp;
using namespace std;
using namespace resip;
using namespace boost;

#define RESIPROCATE_SUBSYSTEM Subsystem::TEST

ostream&
operator<<(ostream& os, const DnsSrvRecord& srv)
{
   os << "pri " << srv.priority() << ' '
      << "weight " << srv.weight() << ' '
      << "port " << srv.port() << ' '
      << "target " << srv.target();
   return os;
}

ostream&
operator<<(ostream& os, const DnsHostRecord& host)
{
   return os << DnsUtil::inet_ntop(host.addr()) << endl;
}

#ifdef USE_IPV6
ostream&
operator<<(ostream& os, const DnsAAAARecord& host)
{
   return os << DnsUtil::inet_ntop(host.v6Address()) << endl;
}
#endif

void
processSrv(const DNSResult<DnsSrvRecord>& r)
{
   InfoLog(<< "SRV result for " << r.domain);
   
   for (vector<DnsSrvRecord>::const_iterator i = r.records.begin(); i != r.records.end(); ++i)
   {
      InfoLog(<< *i);
   }
}
   
void
processA(const DNSResult<DnsHostRecord>& r)
{
   InfoLog(<< "ip4 result for " << r.domain);
   
   for (vector<DnsHostRecord>::const_iterator i = r.records.begin(); i != r.records.end(); ++i)
   {
      InfoLog(<< *i);
   }
}

#ifdef USE_IPV6
void
processAAAA(const DNSResult<DnsAAARecord>& r)
{
   InfoLog(<< "ip6 result for " << r.domain);
   
   for (vector<DnsAAARecord>::const_iterator i = r.records.begin();
            i != r.records.end(); ++i)
   {
      InfoLog(<< *i);
   }
}
#endif

int
main(int argc, char** argv)
{
   Log::initialize(Log::Cout, Log::Debug, argv[0]);

   assert(argc > 1);
   const string domain(argv[1]);

   asio::io_service fifo;

   DnsService dns(fifo);

   if (domain[0] == '_')
   {
      dns.query<Query::SRV>(domain, ptr_fun(&processSrv));
   }
   else
   {
      dns.query<Query::A>(domain, ptr_fun(&processA));

#ifdef USE_IPV6
      dns.query<Query::AAAA>(domain, ptr_fun(&processAAAA));
#endif
   }

   fifo.run();

   return 0;
}
