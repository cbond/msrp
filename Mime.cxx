#include <boost/algorithm/string.hpp>

#include "msrp/System.hxx"
#include "msrp/Mime.hxx"

using namespace msrp;
using namespace std;

bool
Mime::operator<(const Mime& rhs) const
{
   if (mType < rhs.mType)
   {
      return true;
   }
   else if (rhs.mType > mType)
   {
      return false;
   }

   return mSubtype < rhs.mSubtype;
}

bool
Mime::operator==(const Mime& rhs) const
{
   return boost::algorithm::iequals(mType, rhs.mType)
       && boost::algorithm::iequals(mSubtype, rhs.mSubtype);
}

ostream&
msrp::operator<<(ostream& os, const Mime& mime)
{
   os << mime.type();

   if (!mime.subtype().empty())
   {
      os << '/';
      os << mime.subtype();
   }

   for (map<string, string>::const_iterator i = mime.params().begin();
         i != mime.params().end(); ++i)
   {
      os << ';' << i->first;

      if (!i->second.empty())
      {
         os << '=' << i->second;
      }
   }

   return os;
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
