#ifndef MSRP_CONNECTION_HXX
#define MSRP_CONNECTION_HXX

#include <list>

#include <boost/noncopyable.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/signals.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include "msrp/Buffer.hxx"
#include "msrp/Demultiplex.hxx"
#include "msrp/MessageBuffer.hxx"
#include "msrp/Mutex.hxx"
#include "msrp/Scheduler.hxx"
#include "msrp/StreamContext.hxx"

namespace msrp
{

class Connection :
   public boost::noncopyable,
   public boost::signals::trackable,
   public boost::enable_shared_from_this<Connection>
{
   public:
      struct Exception : public msrp::Exception
      {
         Exception(const std::string& s, const ExceptionContext& context) :
            msrp::Exception(s, context)
         {}
      };

      // connect to target(s)
      static boost::shared_ptr<Connection> createAnswer(asio::io_service& service,
            const std::vector<asio::ip::tcp::endpoint>& targets,
            const boost::shared_ptr<asio::ssl::context> identity);

      // bind to local address
      static boost::shared_ptr<Connection> createOffer(asio::io_service& service,
            const asio::ip::tcp::endpoint& bind,
            const boost::shared_ptr<asio::ssl::context> identity);

      // Assume ownership of an existing TCP or TLS connection.  The stream
      // does not have to be connected before you construct Connection.
      Connection(asio::io_service&, std::auto_ptr<asio::ip::tcp::socket>);
      Connection(asio::io_service&, std::auto_ptr<asio::ssl::stream<asio::ip::tcp::socket> >);

      ~Connection();

      enum State
      {
         Listening,
         Connecting,
         Handshaking,
         Connected,
         Disconnected
      };

      enum State state() const;

      asio::io_service& service() const;

      // incoming message demultiplexer
      Demultiplex& demultiplexer();

      // outgoing message scheduler
      Scheduler& scheduler();

      // outgoing stream context
      StreamContext& context();

      unsigned int dependents() const;
      unsigned int& dependents();

      const std::vector<asio::ip::tcp::endpoint>& targets() const;

      void pushTargets(const std::vector<asio::ip::tcp::endpoint>&);

      unsigned int remainingTargets() const;

      bool active() const;

      bool tls() const;

      const asio::ip::tcp::endpoint peer() const;
      const asio::ip::tcp::endpoint local() const;

      const asio::ip::address address() const;

      // !cb! select an outgoing message and send data
      void selectOutgoing();

      // !cb! queue data to be sent
      void send(const asio::const_buffer&);

      void receive(const asio::mutable_buffer&);

      void close();

      // events
      boost::signal1<void, const asio::ip::tcp::endpoint>& onListen();
      boost::signal1<void, const asio::ip::tcp::endpoint>& onConnecting();
      boost::signal1<void, const asio::ip::tcp::endpoint>& onConnect();
      boost::signal1<void, const asio::error&>& onDisconnect();

   private:
      // connect to target(s)
      Connection(asio::io_service& service,
            const std::vector<asio::ip::tcp::endpoint>& targets,
            const boost::shared_ptr<asio::ssl::context> identity);

      // bind to local address
      Connection(asio::io_service& service,
            const asio::ip::tcp::endpoint& bind,
            const boost::shared_ptr<asio::ssl::context> identity);
            
      friend std::ostream& operator<<(std::ostream&, const Connection&);

      typedef asio::ip::tcp::socket TcpStream;
      typedef asio::ssl::stream<asio::ip::tcp::socket> TlsStream;
      typedef asio::ip::tcp::acceptor TcpAcceptor;

      mutable Mutex mMutex;

      asio::io_service& mService;

      const asio::ip::tcp::endpoint getTarget();

      boost::shared_ptr<asio::ssl::context> mIdentity;

      std::vector<asio::ip::tcp::endpoint> mTargets;
      std::vector<asio::ip::tcp::endpoint>::const_iterator mTarget;

      StreamContext mContext;

      boost::scoped_ptr<TcpStream> mTcp;
      boost::scoped_ptr<TlsStream> mTls;
      boost::scoped_ptr<TcpAcceptor> mAccept;

      TcpStream::lowest_layer_type& socket() const;

      boost::scoped_ptr<asio::deadline_timer> mReconnectTimer;

      State mState;

      // outgoing send queue
      Buffer mSend;

      // incoming message buffer
      MessageBuffer mBuffer;

      // message demultiplexer
      Demultiplex mDemux;

      // outgoing message selector
      Scheduler mScheduler;

      unsigned int mDependents;

      boost::signal1<void, const asio::ip::tcp::endpoint> mListen;
      boost::signal1<void, const asio::ip::tcp::endpoint> mConnecting;
      boost::signal1<void, const asio::ip::tcp::endpoint> mConnect;
      boost::shared_ptr< boost::signal1<void, const asio::error&> > mDisconnect;

      void initOffer();
      void init();

      void createStream(bool ip6, bool open);

      void connect();
      void connectHandler(const asio::error&);

      void reconnect(const asio::deadline_timer::duration_type&);
      void reconnectHandler(const asio::error&);

      void receiveHandler(const asio::error&, std::size_t bytes);

      void process();

      void write();
      void writeHandler(bool buffered, const asio::error&, std::size_t bytes);

      void listen(const asio::ip::tcp::endpoint&);
      void acceptHandler(const asio::error&);

      void disconnect(const asio::error&);

      // generate a rejection response
      void reject(boost::shared_ptr<const Message>, unsigned int);

      // encode and send a message
      void send(boost::shared_ptr<const Message>);
};

std::ostream&
operator<<(std::ostream&, const Connection&);

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
