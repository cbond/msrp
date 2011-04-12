#include <cassert>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "msrp/ParseException.hxx"
#include "msrp/Uri.hxx"

using namespace msrp;
using namespace std;

struct Accept
{
   void test(const string& uri)
   {
      try
      {
         Uri x(uri);
         Uri y(x);

         assert(x == y);

         stringstream ss1;
         ss1 << x;

         stringstream ss2;
         ss2 << y;

         assert(ss1.str() == ss2.str());
         assert(ss1.str() == uri);

         Uri z(ss2.str());
         assert(z == y);

         ++mSum;
      }
      catch (const ParseException& e)
      {
         cerr << "acceptance failure: \"" << uri << '"' << endl;
         throw e;
      }
   }

   Accept(unsigned int& sum) : mSum(sum)
   {
      test("msrp:127.0.0.1");
      test("MSRP:validdomain.com");
      test("msrp:foobar.ORG");
      test("msrp://0valid.com");
      test("msrp:foo@bar.com");
      test("msrp:chris@b0nd.net");
      test("msrp:127.0.0.1/a67e68");
      test("msrp:bizzle@a6987.14387.isp.ca:9392");
      test("msrp:a@yvr.co.nz:65535/eefijf001");
      test("msrp:foo.bar.com");
      test("msrps:192.168.0.128");
      test("msrps:255.255.255.255:10/foo");
      test("msrp:foo.bar.com;tcp");
      test("msrps://10.0.0.1;tcp");
      test("msrp:[fe80::2e0:18ff:feb7:202a]");
      test("msrp://user@[a1b0::159:3cff:0a11:0cea]:956/sessionid");
   }

   unsigned int& mSum;
};

struct Reject
{
   void test(const string& uri)
   {
      try
      {
         Uri u(uri);
      }
      catch (const ParseException&)
      {
         ++mSum;
         return;
      }

      cerr << "rejection failure: \"" << uri << '"' << endl;

      throw runtime_error(uri);
   }

   Reject(unsigned int& sum) : mSum(sum)
   {
      test("sip:127.0.0.1");
      test("mrsp:foo.bar.com");
      test("msrp://user@[ffff::fff:ffff:fff:ffg]");
      test("msrp:foo-bar-com");
      test("127.0.0.1");
      test("msrp:foo.");
      test("msrp:.com");
   }

   unsigned int& mSum;
};
   
int
main(int argc, char** argv)
{
   unsigned int sum = 0;

   Accept acceptanceTests(sum);

   Reject rejectionTests(sum);

   cerr << sum << " msrp URI tests passed" << endl;

   return 0;
}
