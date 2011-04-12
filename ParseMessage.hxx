#ifndef MSRP_PARSEMESSAGE_HXX
#define MSRP_PARSEMESSAGE_HXX

#include <boost/spirit.hpp>
#include <boost/spirit/actor.hpp>
#include <boost/spirit/attribute/closure.hpp>
#include <boost/spirit/phoenix/primitives.hpp>
#include <boost/spirit/phoenix/binders.hpp>

#include <resip/stack/Symbols.hxx>

#include "msrp/Message.hxx"

namespace msrp
{

namespace parser
{

struct MessageClosure : boost::spirit::closure<MessageClosure, msrp::Message>
{
   member1 msg;
};

struct Message : boost::spirit::grammar<Message, MessageClosure::context_t>
{
   template<typename ScannerT>
   struct definition
   {
      template<typename Actor, typename T>
         inline boost::spirit::ref_value_actor<T, Actor>
      assign_property(T& ref)
      {
         return boost::spirit::ref_value_actor<T, Actor>(ref);
      }

      // !cb! actors required to disambiguate Message method calls

      struct transaction_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().transaction().assign(first, last);
         }
      };
 
      struct phrase_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().statusPhrase().assign(first, last);
         }
      };
 
      struct status_actor
      {
         template<typename T, typename Value>
         inline void act(T& ref, const Value& v) const
         {
            ref().statusCode() = v;
         }
      };

      struct method_actor
      {
         template<typename T, typename Value>
         inline void act(T& ref, const Value& value) const
         {
            ref().method() = value;
         }
      };

      struct response_actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const&, Iterator const&) const
         {
            ref().method() = msrp::Message::Response;
         }
      };

      definition(const Message& self)
      {
         base = (
             status = boost::spirit::str_p("MSRP")
                >> +boost::spirit::blank_p
                >> transaction
                      [assign_property<transaction_actor>(self.msg)]
                >> +boost::spirit::blank_p
                >> (
                     response[assign_property<response_actor>(self.msg)] | request
                   )
                >> resip::Symbols::CRLF
                >> *header
                >> !boost::spirit::str_p(resip::Symbols::CRLF)
                ,
 
             transaction = +(
                boost::spirit::alpha_p |
                boost::spirit::digit_p | '.' | '-' | '+' | '%' | '='
                ),
 
             request = methods[assign_property<method_actor>(self.msg)],
 
             response =
                boost::spirit::uint_p[assign_property<status_actor>(self.msg)]
                >> +boost::spirit::blank_p
                >> (
                   +(boost::spirit::anychar_p - boost::spirit::eol_p)
                   )
                   [assign_property<phrase_actor>(self.msg)],
 
             header =
                (boost::spirit::alpha_p >> *(boost::spirit::alnum_p | '-'))
                     [boost::spirit::assign_a(headerKey)]
                >> resip::Symbols::COLON
                >> resip::Symbols::SPACE
                >> (
                    *(boost::spirit::anychar_p - boost::spirit::eol_p)
                   )
                   [boost::spirit::insert_at_a(
                      phoenix::bind(&msrp::Message::mHeaders)(self.msg)(),
                      headerKey)
                   ]
                >> resip::Symbols::CRLF
         );
      }

      std::string headerKey;

      boost::spirit::rule<ScannerT> base;
      boost::spirit::subrule<0> status;
      boost::spirit::subrule<1> transaction;
      boost::spirit::subrule<2> request;
      boost::spirit::subrule<3> response;
      boost::spirit::subrule<4> header;

      boost::spirit::rule<ScannerT> const& start() const
      {
         return base;
      }

      struct MethodSymbols : public boost::spirit::symbols<msrp::Message::Method>
      {
         MethodSymbols()
         {
            add("AUTH",   msrp::Message::AUTH)
               ("SEND",   msrp::Message::SEND)
               ("REPORT", msrp::Message::REPORT)
            ;
         }
      } methods;
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
