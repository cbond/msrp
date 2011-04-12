#ifndef MSRP_PARSEURI_HXX
#define MSRP_PARSEURI_HXX

#include <boost/mem_fn.hpp>

#include <boost/spirit/core.hpp>
#include <boost/spirit/actor/push_back_actor.hpp>
#include <boost/spirit/attribute.hpp>
#include <boost/spirit/attribute/closure.hpp>
#include <boost/spirit/phoenix.hpp>

#include "msrp/ParserFactory.hxx"
#include "msrp/Uri.hxx"

namespace msrp
{

namespace parser
{

struct UriClosure : boost::spirit::closure<UriClosure, msrp::Uri>
{
   member1 uri;
};

struct Uri : boost::spirit::grammar<Uri, UriClosure::context_t>
{
   template<typename ScannerT>
   struct definition
   {
      // !cb! We need all these actor definitions to resolve the ambiguities that the
      // parser encounters when trying to assign to overloaded accessors in msrp::Uri.

      template<typename Actor, typename T>
         inline boost::spirit::ref_value_actor<T, Actor>
      assign_property(T& ref)
      {
         return boost::spirit::ref_value_actor<T, Actor>(ref);
      }

      struct scheme_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().scheme().assign(first, last);
         }
      };

      struct delimiter_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const&, Iterator const&) const
         {
            ref().delimiter() = true;
         }
      };

      struct host_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().host().assign(first, last);
         }
      };

      struct session_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().session().assign(first, last);
         }
      };

      struct port_actor
      {
         template<typename T, typename Value>
         inline void act(T& ref, const Value& p) const
         {
            ref().port() = static_cast<unsigned short>(p);
         }
      };

      struct transport_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const&, Iterator const&) const
         {
            ref().transport() = std::string("tcp");
         }
      };

      struct user_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().user().assign(first, last - 1);
         }
      };

      definition(const Uri& self)
      {
         root = scheme        // msrp | msrps
            >> ':'
            >> !boost::spirit::str_p("//")
                  [assign_property<delimiter_actor>(self.uri)]
            >> !userinfo
                  [assign_property<user_actor>(self.uri)]
            >> hostport
            >> !session       // session ID
            >> !transport     // transport
            ;

         typedef boost::spirit::uint_parser<unsigned, 16, 2, 2> Escaped;
         typedef boost::spirit::uint_parser<unsigned, 10, 1, 5> Port;
         typedef boost::spirit::uint_parser<unsigned, 10, 1, 3> IpSegment;
         typedef boost::spirit::uint_parser<unsigned, 16, 1, 4> Ip6Segment;

         scheme =
            boost::spirit::as_lower_d[
               boost::spirit::str_p("msrps") | boost::spirit::str_p("msrp")
            ]
            [assign_property<scheme_actor>(self.uri)];


         userinfo = +(unreserved
               | (boost::spirit::ch_p('%') >> Escaped())
               | (boost::spirit::ch_p('&') | '=' | '+' | '$' | ',' | ';' | '?' | '|')
            ) >> '@';

         unreserved = boost::spirit::alnum_p 
               | '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')';

         transport =
            boost::spirit::as_lower_d
            [
               boost::spirit::str_p(";tcp")[assign_property<transport_actor>(self.uri)]
            ];

         session = boost::spirit::ch_p('/')
            >> (*unreserved)[assign_property<session_actor>(self.uri)];

         hostport =
            host[assign_property<host_actor>(self.uri)]
            >> !(
                  boost::spirit::ch_p(':')
               >> Port()[assign_property<port_actor>(self.uri)]
               );

         host =
            // domain name
            (+(domainlabel >> '.') >> toplabel >> !boost::spirit::ch_p('.')) |

            // IPv4 address
            (IpSegment() >> '.' >> IpSegment() >> '.' >> IpSegment() >> '.' >> IpSegment()) |

            // IPv6 address
            ('[' >> ((hexseq >> "::" >> hexseq) | (boost::spirit::str_p("::") >> hexseq)) >> ']');

         // domain segment
         domainlabel = +(
               (boost::spirit::alnum_p
                >> boost::spirit::ch_p('-')
                >> boost::spirit::alnum_p) | boost::spirit::alnum_p)
            ;

         // toplevel domain
         toplabel = +boost::spirit::alpha_p |
            (boost::spirit::alpha_p >>
               *( boost::spirit::alnum_p
                | boost::spirit::ch_p('-'))
               >> boost::spirit::alnum_p)
            ;

         // segment of an IP6 address
         hexseq = Ip6Segment() >> *(boost::spirit::ch_p(':') >> Ip6Segment());
      }

      // !cb! too many rules to use boost::spirit::subrule cleanly
      boost::spirit::rule<ScannerT> unreserved;
      boost::spirit::rule<ScannerT> root;
      boost::spirit::rule<ScannerT> scheme;
      boost::spirit::rule<ScannerT> userinfo;
      boost::spirit::rule<ScannerT> session;
      boost::spirit::rule<ScannerT> transport;
      boost::spirit::rule<ScannerT> hostport;
      boost::spirit::rule<ScannerT> host;
      boost::spirit::rule<ScannerT> domainlabel;
      boost::spirit::rule<ScannerT> toplabel;
      boost::spirit::rule<ScannerT> hexseq;

      boost::spirit::rule<ScannerT> const& start() const
      {
         return root;
      }
   };
};

struct PathClosure : boost::spirit::closure<PathClosure, msrp::Path>
{
   member1 path;
};

struct Path : boost::spirit::grammar<Path, PathClosure::context_t>
{
   template<typename ScannerT>
   struct definition
   {
      definition(const Path& self)
      {
         using namespace boost::spirit;
         using namespace phoenix;

         const msrp::parser::Uri& grammar = ParserFactory<msrp::parser::Uri>::get();

         root = *(*blank_p >> grammar[push_action<element>(self.path)]);
      }

      boost::spirit::rule<ScannerT> root;
      boost::spirit::rule<ScannerT> const& start() const
      {
         return root;
      }

      template<typename Actor, typename T>
         inline boost::spirit::ref_value_actor<T, Actor>
      push_action(T& ref)
      {
         return boost::spirit::ref_value_actor<T, Actor>(ref);
      }

      struct element
      {
         template<typename T, typename Value>
         inline void act(T& ref, const Value& value) const
         {
            ref().push_back(value);
         }
      };

   };
};

} // namespace parser

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
