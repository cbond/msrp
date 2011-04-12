#include <boost/bind.hpp>

#include "msrp/Buffer.hxx"

using namespace msrp;
using namespace std;
using namespace boost;
using namespace asio;
using namespace resip;

typedef object_pool<array<char, 8192> > Allocator;

static Allocator Blockalloc;

Buffer::Buffer() :
   mSize(0)
{}

Buffer::~Buffer()
{
   for_each(mBuffers.begin(), mBuffers.end(), bind(&Buffer::free, this, _1));
}

const deque<const_buffer>
Buffer::const_buffers() const
{
   deque<const_buffer> dqc(mBuffers.size());

   // !cb! does not deep copy -- const_buffer copy constructor only copies pointers
   copy(mBuffers.begin(), mBuffers.end(), dqc.begin());

   return dqc;
}

void
Buffer::write(const mutable_buffer& buf)
{
   mBuffers.push_back(buf);

   mSize += buffer_size(buf);
}

void
Buffer::write(const Data& data)
{
   size_t s = data.size();
   size_t i = 0;

   while (i < s)
   {
      Allocator::element_type* block = Blockalloc.malloc();

      if (block == 0)
      {
         throw bad_alloc();
      }

      size_t space = min<size_t>(s - i, Allocator::element_type::static_size);

      memcpy(block->c_array(), &data.data()[i], space);

      i += space;

      mBuffers.push_back(mutable_buffer(block->c_array(), space));
   }

   mSize += static_cast<size_t>(i);
}

void
Buffer::shift(size_t size)
{
   mSize -= size;

   while (size > 0)
   {
      assert(!mBuffers.empty());

      mutable_buffer& buf = mBuffers.front();

      size_t currentSize = buffer_size(buf);

      if (size < currentSize)
      {
         // shift data to the front and resize the buffer
         memmove(buffer_cast<void*>(buf),
                 buffer_cast<char*>(buf) + size,
                 currentSize - size);

         buf = mutable_buffer(buffer_cast<void*>(buf), currentSize - size);

         break;
      }
      else
      {
         free(buf);

         mBuffers.pop_front();

         size -= currentSize;
      }
   }
}

bool
Buffer::empty() const
{
   return mBuffers.empty();
}

size_t
Buffer::size() const
{
   return mSize;
}

void
Buffer::free(const mutable_buffer& buf)
{
   Allocator::element_type* block = buffer_cast<Allocator::element_type*>(buf);

   if (Blockalloc.is_from(block))
   {
      Blockalloc.free(block);
   }
   else
   {
      delete[] reinterpret_cast<char*>(block);
   }
}

ostream&
msrp::operator<<(ostream& os, const Buffer& b)
{
   const deque<const_buffer> v = b.const_buffers();

   for (deque<const_buffer>::const_iterator i = v.begin(); i != v.end(); ++i)
   {
      os.write(buffer_cast<const char*>(*i),
         static_cast<streamsize>(buffer_size(*i)));
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