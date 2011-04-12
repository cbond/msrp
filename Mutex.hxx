#ifndef MSRP_MUTEX_HXX
#define MSRP_MUTEX_HXX

#ifdef MSRP_REENTRANT
#include <boost/thread/recursive_mutex.hpp>
#endif

namespace msrp
{

#ifdef MSRP_REENTRANT

typedef boost::recursive_mutex Mutex;
typedef boost::recursive_mutex::scoped_lock ScopedLock;

#else

class Mutex {};

class ScopedLock
{
   public:
      ScopedLock(Mutex&) {}
};

#endif

}

#endif
