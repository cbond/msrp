#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstring>
#include <utility>
#include <sstream>
#include <string>

#include <boost/algorithm/string.hpp>

#include <boost/spirit/phoenix.hpp>

#include <rutil/Logger.hxx>

#include "msrp/System.hxx"
#include "msrp/MessageBuffer.hxx"
#include "msrp/ParseException.hxx"

#define RESIPROCATE_SUBSYSTEM resip::Subsystem::NONE

using namespace msrp;
using namespace boost;
using namespace std;
using namespace asio;

// !cb! Amount of data to withhold from the buffer owner to avoid mistaking an
// end token for contents before an entire message has been received.  Should
// be the maximum size of a transaction ID plus the 7-dash end token delimiter.
const size_t MessageBuffer::Safety = 32;

MessageBuffer::MessageBuffer(size_t size) :
   mBufferSize(size), mStored(0), mState(Status)
{
   mBuffer.reset(new char[mBufferSize]);

   reset();

   // status line parser
   mParser = spirit::str_p("MSRP")
      >> +spirit::blank_p
      >> (
            +( spirit::alpha_p
             | spirit::digit_p
             | '.' | '-' | '+' | '%' | '='
           )
         )[phoenix::var(mTid) = phoenix::construct_<string>(phoenix::arg1, phoenix::arg2)]
      >> spirit::blank_p
      >> (
            boost::spirit::str_p("AUTH")
               [phoenix::var(mMethod) = phoenix::val(Message::AUTH)]
          | boost::spirit::str_p("SEND")
               [phoenix::var(mMethod) = phoenix::val(Message::SEND)]
          | boost::spirit::str_p("REPORT")
               [phoenix::var(mMethod) = phoenix::val(Message::REPORT)]
          | +(boost::spirit::anychar_p - boost::spirit::eol_p)
               [phoenix::var(mMethod) = phoenix::val(Message::Response)]
         )
      >> spirit::ch_p('\r')
      >> spirit::ch_p('\n');
}

void
MessageBuffer::read(size_t size)
{
   if (mState == Complete)
   {
      reset();
   }
   else
   {
      if (mStored == mBufferSize)
      {
         // Use MessageBuffer::erase to free up buffer space after preparsing.
         throw Exception("buffer space exhausted, call erase", codeContext());
      }
   }

   size_t pos = 0;

   if (mState != Status)
   {
      pos = mStored;

      // !cb! Start processing from the last point we left off, except move
      // the buffer iterator backward enough to make sure that the next
      // delimiter we are searching for is not split across two reads.
      pos -= min<size_t>(pos, 16 + mTid.size());
   }

   mStored += size;

   iterator_range<const_iterator> range = make_iterator_range<const_iterator>(
         &mBuffer.get()[pos],
         &mBuffer.get()[mStored]);

   // !cb! iterator advances after each successful delimiter search
   switch (mState)
   {
      case Status:
         if (getTransaction(range))
         {
            mState = Headers;
         }
         else
         {
            break;
         }
      case Headers:
         if (getHeader(range))
         {
            mState = Content;
         }
      case Content:
         if (getEndToken(range))
         {
            mState = Complete;
         }
         else
         {
            setContentRange();
         }
      case Complete:
         break;
   }
}

shared_ptr<Message>
MessageBuffer::parse(const ParseMode parseMode) const
{
   // .cb. not enough data to parse a message?
   if ((mState != Content && mState != Complete)
         || empty(mStatusRange)
         || empty(mHeaderRange))
   {
      return shared_ptr<Message>();
   }

   const size_t s = distance(begin(mStatusRange), end(mHeaderRange));

   shared_ptr<Message> m = Message::factory(const_buffer(begin(mStatusRange), s));
   if (m)
   {
      m->status() = mStatus;

      m->contents() = resip::Data();

      if (!empty(mContentRange))
      {
         switch (parseMode)
         {
            case OverlayContents:
               m->contents() = resip::Data(resip::Data::Borrow,
                  mContentRange.begin(),
                  mContentRange.size());
               break;
            case CopyContents:
               m->contents().append(begin(mContentRange), size(mContentRange));
               break;
            case NoContents:
               break;
         }
      }
   }

   return m;
}

void
MessageBuffer::reset()
{
   // !cb! If another message is lumped on to the end of this one, then shift
   // the remaining contents to the front of the buffer so that they can be
   // processed in the next MessageBuffer::read.
 
   if (mState == Complete)
   {
      const_iterator i = end(mTokenRange);

      while (i < mBuffer.get() + mStored && isspace(*i))
      {
         ++i;
      }

      mStored -= offset(i);

      memmove(mBuffer.get(), i, mStored);
   }
   else
   {
      mStored = 0;
   }

   mTid.clear();

   mState = Status;

   resetRanges();
}

void
MessageBuffer::setContentRange()
{
   mContentRange = iterator_range<const_iterator>(
      reinterpret_cast<const_iterator>(0),
      reinterpret_cast<const_iterator>(0));

   if (state() == Content)
   {
      if (empty(mStatusRange) && empty(mHeaderRange))
      {
         // message buffer has been erased, contents consumes all input
         // minus the last few bytes that may constitute part of the end
         // of transaction token.
         const size_t s = mStored - min<size_t>(mStored, Safety);

         if (s)
         {
            mContentRange = make_iterator_range(mBuffer.get(), &mBuffer.get()[s]);
         }
      }
      else if (!empty(mHeaderRange))
      {
         const size_t s = mStored - offset(end(mHeaderRange));

         if (s > Safety)
         {
            mContentRange = make_iterator_range(end(mHeaderRange),
               const_cast<const_iterator>(&mBuffer.get()[mStored - Safety]));
         }
      }
   }

   mStatus = Message::Streaming;
}

bool
MessageBuffer::getTransaction(iterator_range<const_iterator>& i)
{
   spirit::parse_info<> result = spirit::parse(begin(i), end(i), mParser);

   if (result.hit)
   {
      if (!mTid.empty())
      {
         mStatusRange = make_iterator_range(begin(i), result.stop);

         // !cb! result.stop iterator is within begin(i) and end(i)
         i = make_iterator_range(result.stop, end(i));

         return true;
      }
   }

   return false;
}

bool
MessageBuffer::getHeader(iterator_range<const_iterator>& r)
{
   iterator_range<const_iterator>::const_iterator i = begin(r);

   iterator_range<const_iterator>::const_iterator start = i;

   while (distance(i, end(r)) >= 4)
   {
      if (*i++ == '\r'
       && *i++ == '\n'
       && *i++ == '\r'
       && *i++ == '\n')
      {
         mHeaderRange = make_iterator_range(start, i);

         r = make_iterator_range(i, end(r));

         return true;
      }
   }

   return false;
}

const string
MessageBuffer::endToken() const
{
   assert(!mTid.empty());

   stringstream ss;
   ss << "-------";
   ss << mTid;

   return ss.str();
}

MessageBuffer::const_iterator
MessageBuffer::reverseKey(const_iterator i, size_t bytes) const
{
   const string marker = endToken();

   if (bytes >= marker.size())
   {
      typedef unsigned int Key;

      // Search the message 4 bytes at a time for the end token.
      const Key key = static_cast<Key>('-')
                    | static_cast<Key>('-') << 8
                    | static_cast<Key>('-') << 16
                    | static_cast<Key>('-') << 24;

      const Key* a = reinterpret_cast<const Key*>(i - bytes);
      const Key* b = reinterpret_cast<const Key*>(i - sizeof(Key));

      while (b >= a)
      {
         if (*b == key)
         {
            return reinterpret_cast<const_iterator>(b);
         }
         --b;
      }
   }

   return 0;
}

bool
MessageBuffer::getEndToken(iterator_range<const_iterator>& r)
{
   // !cb! search backwards for the end token
   const_iterator keypos = reverseKey(end(r), size(r));

   if (keypos)
   {
      const string marker = endToken();

      while (keypos < end(r) && keypos[0] == '-')
      {
         ++keypos;
      }

      advance(keypos, -7);

      if (strncmp(keypos, marker.c_str(), marker.size()) == 0)
      {
         mTokenRange = make_iterator_range(keypos, keypos + marker.size() + 1); // + 1 = [+$#]

         if (empty(mHeaderRange))
         {
            if (!empty(mStatusRange))
            {
               // !cb! If no header range has been set, the message likely contains no
               // contents and thus no double newline after the headers, so we can move
               // the header range to between mStatusRange and mTokenRange.  (The end
               // token immediately follows the headers in this case.)
               mHeaderRange = make_iterator_range(begin(mStatusRange), begin(mTokenRange));
            }
            else
            {
               // !cb! erase has been called; content spans entire buffer
               mContentRange = make_iterator_range(const_cast<const_iterator>(mBuffer.get()),
                     begin(mTokenRange));
            }
         }
         else
         {
            mContentRange = make_iterator_range(end(mHeaderRange), begin(mTokenRange));
         }

         char status = end(mTokenRange)[-1];

         switch (status)
         {
            case '+':
               mStatus = Message::Continued;
               break;
            case '$':
               mStatus = Message::Complete;
               break;
            case '#':
               mStatus = Message::Interrupted;
               break;
            default:
               // !cb! message incomplete?
               return false;
         }

         return true;
      }
   }

   return false;
}

const_buffer
MessageBuffer::contents() const
{
   if (empty(mContentRange))
   {
      return const_buffer();
   }

   return const_buffer(begin(mContentRange), size(mContentRange));
}

size_t
MessageBuffer::offset(const_iterator i) const
{
   return distance(const_cast<const_iterator>(mBuffer.get()), i);
}

void
MessageBuffer::erase()
{
   if (mState == Content)
   {
      if (empty(mTokenRange) && !empty(mContentRange))
      {
         const size_t off = offset(end(mContentRange));

         if (off < mStored && off + Safety == mStored)
         {
            memmove(mBuffer.get(), &mBuffer.get()[off], Safety);

            mStored = Safety;

            resetRanges();

            return;
         }
      }
   }

   mStored = 0;

   resetRanges();
}

void
MessageBuffer::resetRanges()
{
   const const_iterator invalid = 0;

   mStatusRange  = iterator_range<const_iterator>(invalid, invalid);
   mHeaderRange  = iterator_range<const_iterator>(invalid, invalid);
   mContentRange = iterator_range<const_iterator>(invalid, invalid);
   mTokenRange   = iterator_range<const_iterator>(invalid, invalid);
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
