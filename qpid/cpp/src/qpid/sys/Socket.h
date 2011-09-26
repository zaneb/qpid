#ifndef _sys_Socket_h
#define _sys_Socket_h

/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include "qpid/sys/IOHandle.h"
#include "qpid/sys/IntegerTypes.h"
#include "qpid/CommonImportExport.h"
#include <string>

namespace qpid {
namespace sys {

class Duration;
class SocketAddress;

class GenericSocket: public IOHandle
{
public:
    /** Create a socket wrapper for descriptor. */
    GenericSocket();

    /** Set socket non blocking */
    virtual void setNonblocking() const = 0;

    virtual void setTcpNoDelay(bool nd) const = 0;

    virtual void connect(const std::string& host, uint16_t port) const = 0;

    virtual void close() const = 0;

    /** Returns the "socket name" ie the address bound to
     * the near end of the socket
     */
    QPID_COMMON_EXTERN std::string getSockname() const;

    /** Returns the "peer name" ie the address bound to
     * the remote end of the socket
     */
    std::string getPeername() const;

    /**
     * Returns an address (host and port) for the remote end of the
     * socket
     */
    QPID_COMMON_EXTERN std::string getPeerAddress() const;
    /**
     * Returns an address (host and port) for the local end of the
     * socket
     */
    QPID_COMMON_EXTERN std::string getLocalAddress() const;

    /**
     * Returns the full address of the connection: local and remote host and
     * port.
     */
    QPID_COMMON_EXTERN std::string getFullAddress() const {
        return getLocalAddress() + "-" + getPeerAddress();
    }

    QPID_COMMON_EXTERN uint16_t getLocalPort() const;
    uint16_t getRemotePort() const;

    /**
     * Returns the error code stored in the socket.  This may be used
     * to determine the result of a non-blocking connect.
     */
    int getError() const;

    /** Accept a connection from a socket that is already listening
     * and has an incoming connection
     */
    virtual GenericSocket* accept() const = 0;

    virtual int read(void *buf, size_t count) const = 0;
    virtual int write(const void *buf, size_t count) const = 0;

protected:
    GenericSocket(IOHandlePrivate *h);
    mutable std::string connectname;
};

class Socket : public GenericSocket
{
public:
    /** Create a socket wrapper for descriptor. */
    QPID_COMMON_EXTERN Socket();
    Socket(IOHandlePrivate*);

    /** Set timeout for read and write */
    void setTimeout(const Duration& interval) const;

    /** Set socket non blocking */
    void setNonblocking() const;

    QPID_COMMON_EXTERN void setTcpNoDelay(bool nd=true) const;

    QPID_COMMON_EXTERN void connect(const std::string& host, uint16_t port) const;
    QPID_COMMON_EXTERN void connect(const SocketAddress&) const;

    QPID_COMMON_EXTERN void close() const;

    /** Bind to a port and start listening.
     *@param port 0 means choose an available port.
     *@param backlog maximum number of pending connections.
     *@return The bound port.
     */
    QPID_COMMON_EXTERN int listen(uint16_t port = 0, int backlog = 10) const;
    QPID_COMMON_EXTERN int listen(const SocketAddress&, int backlog = 10) const;


    /** Accept a connection from a socket that is already listening
     * and has an incoming connection
     */
    QPID_COMMON_EXTERN virtual GenericSocket* accept() const;

    // TODO The following are raw operations, maybe they need better wrapping?
    QPID_COMMON_EXTERN int read(void *buf, size_t count) const;
    QPID_COMMON_EXTERN int write(const void *buf, size_t count) const;

private:
    /** Create socket */
    void createSocket(const SocketAddress&) const;

    mutable bool nonblocking;
    mutable bool nodelay;
};

}}
#endif  /*!_sys_Socket_h*/
