#ifndef MSRP_AUTHTUPLE_HXX
#define MSRP_AUTHTUPLE_HXX

// !cb! This stuff is not really working correctly.  Since we are not going
// to need this for the next milestone, just disable it until we have time
// to refactor it.
#ifdef ENABLE_AUTHTUPLE

#include <map>
#include <ostream>
#include <string>
#include <vector>

#include <boost/bind.hpp>
#include <boost/spirit/debug.hpp>

#include <rutil/Data.hxx>

#include "msrp/Exception.hxx"
#include "msrp/ParseException.hxx"
#include "msrp/LazyField.hxx"
#include "msrp/LiteralBoolean.hxx"

namespace msrp
{

// authentication parameters

struct nc :
   public LazyField::Storage<
      nc,
      unsigned int,
      boost::spirit::uint_parser<unsigned, 16, 8, 8>
   >
{
   static const std::string Key;
};

struct algorithm : public LazyField::Data
{
   static const std::string Key;
};

struct cnonce : public LazyField::Data
{
   static const std::string Key;
};

struct nonce : public LazyField::Data
{
   static const std::string Key;
};

struct opaque : public LazyField::Data
{
   static const std::string Key;
};

struct realm : public LazyField::Data
{
   static const std::string Key;
};

struct rspauth : public LazyField::Data
{
   static const std::string Key;
};

struct stale : public LazyField::Storage<stale, bool, parser::LiteralBoolean>
{
   static const std::string Key;
};

struct username : public LazyField::Data
{
   static const std::string Key;
};

// qop option list parser
struct QopClosure :
   public boost::spirit::closure<QopClosure, std::vector<std::string> >
{
   member1 qop;
};

struct QopParser : boost::spirit::grammar<QopParser, QopClosure::context_t>
{
   template<typename ScannerT>
   struct definition
   {
      template<typename Actor, typename T>
         inline boost::spirit::ref_value_actor<T, Actor>
      assignment(T& ref)
      {
         return boost::spirit::ref_value_actor<T, Actor>(ref);
      }

      struct actor
      {
         template<typename T, typename Iterator>
         inline void act(T& ref, Iterator const& first, Iterator const& last) const
         {
            ref().push_back(std::string(first, last));
         }
      };

      definition(const QopParser& self)
      {
         root = boost::spirit::list_p(
                   (*(boost::spirit::anychar_p - boost::spirit::ch_p(',')))
                      [assignment<actor>(self.qop)],
                ',');
      };

      boost::spirit::rule<ScannerT> root;
      boost::spirit::rule<ScannerT> const& start() const
      {
         return root;
      }
   };
};

struct qop :
   public LazyField::Storage<
      qop,
      std::vector<std::string>,
      QopParser
   >
{
   static const std::string Key;
};

class AuthTuple
{
   public:
      AuthTuple()
      {}

      const std::string& scheme() const { return mScheme; }
      std::string& scheme() { return mScheme; }

      template<typename ParamT>
      inline bool exists() const
      {
         return exists(ParamT::Key);
      }

      inline bool exists(const std::string& id) const
      {
         return mRaw.find(id) != mRaw.end();
      }

      inline const std::string& param(const std::string& id) const
      {
         using std::map;
         using std::string;

         map<string, string>::const_iterator i = mRaw.find(id);
         if (i == mRaw.end())
         {
            throw ParseException(id, codeContext());
         }

         return i->second;
      }

      inline std::string& param(const std::string& id)
      {
         return mRaw[id];
      }

      std::map<std::string, std::string>& params()
      {
         return mRaw;
      }

      template<typename T>
      typename T::Value& param()
      {
         T* p;
         get(p);
         return p->get(mRaw);
      }

      template<typename T>
      const typename T::Value& param() const
      {
         T* p;
         get(p);
         return p->getConst(mRaw);
      }

      void preparse();

   private:
      friend std::ostream& operator<<(std::ostream&, const AuthTuple&);

      std::string mScheme;

      // unparsed
      mutable std::map<std::string, std::string> mRaw;

      // parsed
      mutable struct
      {
         msrp::nc nc;
         msrp::stale stale;
         msrp::qop qop;
      } mParams;

      // !cb! Hack for Microsoft compiler.  Can be replaced with specialized template
      // solution once we can upgrade to the newer compiler (8.0).
      void get(msrp::nc*& p) const { p = &mParams.nc; }
      void get(msrp::qop*& p) const { p = &mParams.qop; }
      void get(msrp::stale*& p) const { p = &mParams.stale; }
      template<typename T> void get(T*& p) const { p = 0; }
};

std::ostream&
operator<<(std::ostream&, const AuthTuple&);

// nc
template<> inline bool
AuthTuple::exists<nc>() const
{
   return mParams.nc.parsed() || mRaw.find(nc::Key) != mRaw.end();
}

// stale
template<> inline bool
AuthTuple::exists<stale>() const
{
   return mParams.stale.parsed() || mRaw.find(stale::Key) != mRaw.end();
}

// qop
template<> inline bool
AuthTuple::exists<qop>() const
{
   return mParams.qop.parsed() || mRaw.find(qop::Key) != mRaw.end();
}

}

#endif // ENABLE_AUTHTUPLE

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
