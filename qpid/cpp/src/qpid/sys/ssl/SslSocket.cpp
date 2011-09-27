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

#include "qpid/sys/ssl/SslSocket.h"
#include "qpid/sys/ssl/check.h"
#include "qpid/sys/ssl/util.h"
#include "qpid/Exception.h"
#include "qpid/sys/posix/check.h"
#include "qpid/sys/posix/PrivatePosix.h"
#include "qpid/log/Statement.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstdlib>
#include <string.h>
#include <iostream>

#include <private/pprio.h>
#include <nss.h>
#include <pk11pub.h>
#include <ssl.h>
#include <key.h>

#include <boost/format.hpp>

namespace qpid {
namespace sys {
namespace ssl {

namespace {
const std::string DOMAIN_SEPARATOR("@");
const std::string DC_SEPARATOR(".");
const std::string DC("DC");
const std::string DN_DELIMS(" ,=");

std::string getDomainFromSubject(std::string subject)
{
    std::string::size_type last = subject.find_first_not_of(DN_DELIMS, 0);
    std::string::size_type i = subject.find_first_of(DN_DELIMS, last);

    std::string domain;
    bool nextTokenIsDC = false;
    while (std::string::npos != i || std::string::npos != last)
    {
        std::string token = subject.substr(last, i - last);
        if (nextTokenIsDC) {
            if (domain.size()) domain += DC_SEPARATOR;
            domain += token;
            nextTokenIsDC = false;
        } else if (token == DC) {
            nextTokenIsDC = true;
        }
        last = subject.find_first_not_of(DN_DELIMS, i);
        i = subject.find_first_of(DN_DELIMS, last);
    }
    return domain;
}

}

SslSocket::SslSocket() : socket(0), prototype(0)
{
    impl->fd = ::socket (PF_INET, SOCK_STREAM, 0);
    if (impl->fd < 0) throw QPID_POSIX_ERROR(errno);
    socket = SSL_ImportFD(0, PR_ImportTCPSocket(impl->fd));
}

/**
 * This form of the constructor is used with the server-side sockets
 * returned from accept. Because we use posix accept rather than
 * PR_Accept, we have to reset the handshake.
 */
SslSocket::SslSocket(IOHandlePrivate* ioph, PRFileDesc* model) : GenericSocket(ioph), socket(0), prototype(0)
{
    socket = SSL_ImportFD(model, PR_ImportTCPSocket(impl->fd));
    NSS_CHECK(SSL_ResetHandshake(socket, true));
}

void SslSocket::setNonblocking() const
{
    PRSocketOptionData option;
    option.option = PR_SockOpt_Nonblocking;
    option.value.non_blocking = true;
    PR_SetSocketOption(socket, &option);
}

void SslSocket::connect(const std::string& host, uint16_t port) const
{
    std::stringstream namestream;
    namestream << host << ":" << port;
    connectname = namestream.str();

    void* arg;
    // Use the connection's cert-name if it has one; else use global cert-name
    if (certname != "") {
        arg = const_cast<char*>(certname.c_str());
    } else if (SslOptions::global.certName.empty()) {
        arg = 0;
    } else {
        arg = const_cast<char*>(SslOptions::global.certName.c_str());
    }
    NSS_CHECK(SSL_GetClientAuthDataHook(socket, NSS_GetClientAuthData, arg));
    NSS_CHECK(SSL_SetURL(socket, host.data()));

    char hostBuffer[PR_NETDB_BUF_SIZE];
    PRHostEnt hostEntry;
    PR_CHECK(PR_GetHostByName(host.data(), hostBuffer, PR_NETDB_BUF_SIZE, &hostEntry));
    PRNetAddr address;
    int value = PR_EnumerateHostEnt(0, &hostEntry, port, &address);
    if (value < 0) {
        throw Exception(QPID_MSG("Error getting address for host: " << ErrorString()));
    } else if (value == 0) {
        throw Exception(QPID_MSG("Could not resolve address for host."));
    }
    PR_CHECK(PR_Connect(socket, &address, PR_INTERVAL_NO_TIMEOUT));
    NSS_CHECK(SSL_ForceHandshake(socket));
}

void SslSocket::close() const
{
    if (impl->fd > 0) {
        PR_Close(socket);
        impl->fd = -1;
    }
}

int SslSocket::listen(uint16_t port, int backlog, const std::string& certName, bool clientAuth) const
{
    //configure prototype socket:
    prototype = SSL_ImportFD(0, PR_NewTCPSocket());
    if (clientAuth) {
        NSS_CHECK(SSL_OptionSet(prototype, SSL_REQUEST_CERTIFICATE, PR_TRUE));
        NSS_CHECK(SSL_OptionSet(prototype, SSL_REQUIRE_CERTIFICATE, PR_TRUE));
    }

    //get certificate and key (is this the correct way?)
    CERTCertificate *cert = PK11_FindCertFromNickname(const_cast<char*>(certName.c_str()), 0);
    if (!cert) throw Exception(QPID_MSG("Failed to load certificate '" << certName << "'"));
    SECKEYPrivateKey *key = PK11_FindKeyByAnyCert(cert, 0);
    if (!key) throw Exception(QPID_MSG("Failed to retrieve private key from certificate"));
    NSS_CHECK(SSL_ConfigSecureServer(prototype, cert, key, NSS_FindCertKEAType(cert)));
    SECKEY_DestroyPrivateKey(key);
    CERT_DestroyCertificate(cert);

    //bind and listen
    const int& socket = impl->fd;
    int yes=1;
    QPID_POSIX_CHECK(setsockopt(socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)));
    struct sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = 0;
    if (::bind(socket, (struct sockaddr*)&name, sizeof(name)) < 0)
        throw Exception(QPID_MSG("Can't bind to port " << port << ": " << strError(errno)));
    if (::listen(socket, backlog) < 0)
        throw Exception(QPID_MSG("Can't listen on port " << port << ": " << strError(errno)));

    socklen_t namelen = sizeof(name);
    if (::getsockname(socket, (struct sockaddr*)&name, &namelen) < 0)
        throw QPID_POSIX_ERROR(errno);

    return ntohs(name.sin_port);
}

GenericSocket* SslSocket::accept() const
{
    QPID_LOG(trace, "Accepting SSL connection.");
    int afd = ::accept(impl->fd, 0, 0);
    if ( afd >= 0) {
        return new SslSocket(new IOHandlePrivate(afd), prototype);
    } else if (errno == EAGAIN) {
        return 0;
    } else {
        throw QPID_POSIX_ERROR(errno);
    }
}

GenericSocket* SslOptionalSocket::accept() const
{
    QPID_LOG(trace, "Accepting connection with optional SSL wrapper.");
    int afd = ::accept(impl->fd, 0, 0);
    if (afd >= 0) {
        char buf[4];
        if (recv(afd, buf, sizeof(buf), MSG_PEEK) != sizeof(buf)) {
            int err = errno;
            ::close(afd);
            throw QPID_POSIX_ERROR(err);
        }
        if (memcmp(buf, "AMQP", sizeof(buf)) == 0) {
            QPID_LOG(trace, "Accepted Plaintext connection.");
            return new Socket(new IOHandlePrivate(afd));
        } else {
            QPID_LOG(trace, "Accepted SSL connection.");
            return new SslSocket(new IOHandlePrivate(afd), prototype);
        }
    } else if (errno == EAGAIN) {
        return 0;
    } else {
        throw QPID_POSIX_ERROR(errno);
    }
}

int SslSocket::read(void *buf, size_t count) const
{
    return PR_Read(socket, buf, count);
}

int SslSocket::write(const void *buf, size_t count) const
{
    return PR_Write(socket, buf, count);
}

void SslSocket::setTcpNoDelay(bool nodelay) const
{
    if (nodelay) {
        PRSocketOptionData option;
        option.option = PR_SockOpt_NoDelay;
        option.value.no_delay = true;
        PR_SetSocketOption(socket, &option);
    }
}

void SslSocket::setCertName(const std::string& name)
{
    certname = name;
}


/** get the bit length of the current cipher's key */
int SslSocket::getKeyLen() const
{
    int enabled = 0;
    int keySize = 0;
    SECStatus   rc;

    rc = SSL_SecurityStatus( socket,
                             &enabled,
                             NULL,
                             NULL,
                             &keySize,
                             NULL, NULL );
    if (rc == SECSuccess && enabled) {
        return keySize;
    }
    return 0;
}

std::string SslSocket::getClientAuthId() const
{
    std::string authId;
    CERTCertificate* cert = SSL_PeerCertificate(socket);
    if (cert) {
        authId = CERT_GetCommonName(&(cert->subject));
        /*
         * The NSS function CERT_GetDomainComponentName only returns
         * the last component of the domain name, so we have to parse
         * the subject manually to extract the full domain.
         */
        std::string domain = getDomainFromSubject(cert->subjectName);
        if (!domain.empty()) {
            authId += DOMAIN_SEPARATOR;
            authId += domain;
        }
        CERT_DestroyCertificate(cert);
    }
    return authId;
}

}}} // namespace qpid::sys::ssl
