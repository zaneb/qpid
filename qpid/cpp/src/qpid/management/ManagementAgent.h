#ifndef _ManagementAgent_
#define _ManagementAgent_

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
#include "qpid/broker/BrokerImportExport.h"
#include "qpid/Options.h"
#include "qpid/broker/Exchange.h"
#include "qpid/framing/Uuid.h"
#include "qpid/sys/Mutex.h"
#include "qpid/sys/Timer.h"
#include "qpid/broker/ConnectionToken.h"
#include "qpid/management/ManagementObject.h"
#include "qpid/management/ManagementEvent.h"
#include "qpid/management/Manageable.h"
#include "qmf/org/apache/qpid/broker/Agent.h"
#include "qpid/types/Variant.h"
#include <qpid/framing/AMQFrame.h>
#include <qpid/framing/FieldValue.h>
#include <qpid/framing/ResizableBuffer.h>
#include <memory>
#include <string>
#include <map>

namespace qpid {
namespace broker {
class ConnectionState;
}
namespace management {

class ManagementAgent
{
private:

    int threadPoolSize;

public:
    typedef enum {
    SEV_EMERG = 0,
    SEV_ALERT = 1,
    SEV_CRIT  = 2,
    SEV_ERROR = 3,
    SEV_WARN  = 4,
    SEV_NOTE  = 5,
    SEV_INFO  = 6,
    SEV_DEBUG = 7,
    SEV_DEFAULT = 8
    } severity_t;


    ManagementAgent (const bool qmfV1, const bool qmfV2);
    virtual ~ManagementAgent ();

    /** Called before plugins are initialized */
    void configure       (const std::string& dataDir, uint16_t interval,
                          qpid::broker::Broker* broker, int threadPoolSize);
    /** Called after plugins are initialized. */
    void pluginsInitialized();

    /** Called by cluster to suppress management output during update. */
    void suppress(bool s) { suppressed = s; }

    void setName(const std::string& vendor,
                 const std::string& product,
                 const std::string& instance="");
    void getName(std::string& vendor, std::string& product, std::string& instance);
    const std::string& getAddress();

    void setInterval(uint16_t _interval) { interval = _interval; }
    void setExchange(qpid::broker::Exchange::shared_ptr mgmtExchange,
                     qpid::broker::Exchange::shared_ptr directExchange);
    void setExchangeV2(qpid::broker::Exchange::shared_ptr topicExchange,
                       qpid::broker::Exchange::shared_ptr directExchange);

    int  getMaxThreads   () { return threadPoolSize; }
    QPID_BROKER_EXTERN void registerClass   (const std::string& packageName,
                                             const std::string& className,
                                             uint8_t*    md5Sum,
                                             ManagementObject::writeSchemaCall_t schemaCall);
    QPID_BROKER_EXTERN void registerEvent   (const std::string& packageName,
                                             const std::string& eventName,
                                             uint8_t*    md5Sum,
                                             ManagementObject::writeSchemaCall_t schemaCall);
    QPID_BROKER_EXTERN ObjectId addObject   (ManagementObject* object,
                                             uint64_t          persistId = 0,
                                             bool              persistent = false);
    QPID_BROKER_EXTERN ObjectId addObject   (ManagementObject*  object,
                                             const std::string& key,
                                             bool               persistent = false);
    QPID_BROKER_EXTERN void raiseEvent(const ManagementEvent& event,
                                       severity_t severity = SEV_DEFAULT);
    QPID_BROKER_EXTERN void clientAdded     (const std::string& routingKey);

    QPID_BROKER_EXTERN void clusterUpdate();

    bool dispatchCommand (qpid::broker::Deliverable&       msg,
                          const std::string&         routingKey,
                          const framing::FieldTable* args,
                          const bool topic,
                          int qmfVersion);

    /** Disallow a method. Attempts to call it will receive an exception with message. */
    void disallow(const std::string& className, const std::string& methodName, const std::string& message);

    /** Disallow all QMFv1 methods (used in clustered brokers). */
    void disallowV1Methods() { disallowAllV1Methods = true; }

    /** Serialize my schemas as a binary blob into schemaOut */
    void exportSchemas(std::string& schemaOut);

    /** Serialize my remote-agent map as a binary blob into agentsOut */
    void exportAgents(std::string& agentsOut);

    /** Decode a serialized schemas and add to my schema cache */
    void importSchemas(framing::Buffer& inBuf);

    /** Decode a serialized agent map */
    void importAgents(framing::Buffer& inBuf);

    // these are in support of the managementSetup-state stuff, for synch'ing clustered brokers
    uint64_t getNextObjectId(void) { return nextObjectId; }
    void setNextObjectId(uint64_t o) { nextObjectId = o; }

    uint16_t getBootSequence(void) { return bootSequence; }
    void setBootSequence(uint16_t b) { bootSequence = b; writeData(); }

    const framing::Uuid& getUuid() const { return uuid; }
    void setUuid(const framing::Uuid& id) { uuid = id; writeData(); }

    static types::Variant::Map toMap(const framing::FieldTable& from);

    // For Clustering: management objects that have been marked as
    // "deleted", but are waiting for their last published object
    // update are not visible to the cluster replication code.  These
    // interfaces allow clustering to gather up all the management
    // objects that are deleted in order to allow all clustered
    // brokers to publish the same set of deleted objects.

    class DeletedObject {
      public:
        typedef boost::shared_ptr<DeletedObject> shared_ptr;
        DeletedObject(ManagementObject *, bool v1, bool v2);
        DeletedObject( const std::string &encoded );
        ~DeletedObject() {};
        void encode( std::string& toBuffer );
        const std::string getKey() const {
            // used to batch up objects of the same class type
            return std::string(packageName + std::string(":") + className);
        }

      private:
        friend class ManagementAgent;

        std::string packageName;
        std::string className;
        std::string objectId;

        std::string encodedV1Config;    // qmfv1 properties
        std::string encodedV1Inst;      // qmfv1 statistics
        qpid::types::Variant::Map encodedV2;
    };

    typedef std::vector<DeletedObject::shared_ptr> DeletedObjectList;

    /** returns a snapshot of all currently deleted management objects. */
    void exportDeletedObjects( DeletedObjectList& outList );

    /** Import a list of deleted objects to send on next publish interval. */
    void importDeletedObjects( const DeletedObjectList& inList );

private:
    struct Periodic : public qpid::sys::TimerTask
    {
        ManagementAgent& agent;

        Periodic (ManagementAgent& agent, uint32_t seconds);
        virtual ~Periodic ();
        void fire ();
    };

    //  Storage for tracking remote management agents, attached via the client
    //  management agent API.
    //
    struct RemoteAgent : public Manageable
    {
        ManagementAgent&  agent;
        uint32_t          brokerBank;
        uint32_t          agentBank;
        std::string       routingKey;
        ObjectId          connectionRef;
        qmf::org::apache::qpid::broker::Agent*    mgmtObject;
        RemoteAgent(ManagementAgent& _agent) : agent(_agent), mgmtObject(0) {}
        ManagementObject* GetManagementObject (void) const { return mgmtObject; }

        virtual ~RemoteAgent ();
        void mapEncode(qpid::types::Variant::Map& _map) const;
        void mapDecode(const qpid::types::Variant::Map& _map);
    };

    typedef std::map<ObjectId, boost::shared_ptr<RemoteAgent> > RemoteAgentMap;

    //  Storage for known schema classes:
    //
    //  SchemaClassKey     -- Key elements for map lookups
    //  SchemaClassKeyComp -- Comparison class for SchemaClassKey
    //  SchemaClass        -- Non-key elements for classes
    //
    struct SchemaClassKey
    {
        std::string name;
        uint8_t     hash[16];

        void mapEncode(qpid::types::Variant::Map& _map) const;
        void mapDecode(const qpid::types::Variant::Map& _map);
        void encode(framing::Buffer& buffer) const;
        void decode(framing::Buffer& buffer);
        uint32_t encodedBufSize() const;
    };

    struct SchemaClassKeyComp
    {
        bool operator() (const SchemaClassKey& lhs, const SchemaClassKey& rhs) const
        {
            if (lhs.name != rhs.name)
                return lhs.name < rhs.name;
            else
                for (int i = 0; i < 16; i++)
                    if (lhs.hash[i] != rhs.hash[i])
                        return lhs.hash[i] < rhs.hash[i];
            return false;
        }
    };


    struct SchemaClass
    {
        uint8_t  kind;
        ManagementObject::writeSchemaCall_t writeSchemaCall;
        std::string data;
        uint32_t pendingSequence;

        SchemaClass(uint8_t _kind=0, uint32_t seq=0) :
            kind(_kind), writeSchemaCall(0), pendingSequence(seq) {}
        SchemaClass(uint8_t _kind, ManagementObject::writeSchemaCall_t call) :
            kind(_kind), writeSchemaCall(call), pendingSequence(0) {}
        bool hasSchema () { return (writeSchemaCall != 0) || !data.empty(); }
        void appendSchema (framing::Buffer& buf);

        void mapEncode(qpid::types::Variant::Map& _map) const;
        void mapDecode(const qpid::types::Variant::Map& _map);
    };

    typedef std::map<SchemaClassKey, SchemaClass, SchemaClassKeyComp> ClassMap;
    typedef std::map<std::string, ClassMap> PackageMap;

    RemoteAgentMap               remoteAgents;
    PackageMap                   packages;

    //
    // Protected by userLock
    //
    ManagementObjectMap          managementObjects;

    //
    // Protected by addLock
    //
    ManagementObjectVector       newManagementObjects;

    framing::Uuid                uuid;

    //
    // Lock hierarchy:  If a thread needs to take both addLock and userLock,
    // it MUST take userLock first, then addLock.
    //
    sys::Mutex userLock;
    sys::Mutex addLock;

    qpid::broker::Exchange::shared_ptr mExchange;
    qpid::broker::Exchange::shared_ptr dExchange;
    qpid::broker::Exchange::shared_ptr v2Topic;
    qpid::broker::Exchange::shared_ptr v2Direct;
    std::string                  dataDir;
    uint16_t                     interval;
    qpid::broker::Broker*        broker;
    qpid::sys::Timer*            timer;
    uint16_t                     bootSequence;
    uint32_t                     nextObjectId;
    uint32_t                     brokerBank;
    uint32_t                     nextRemoteBank;
    uint32_t                     nextRequestSequence;
    bool                         clientWasAdded;
    const qpid::sys::AbsTime     startTime;
    bool                         suppressed;

    typedef std::pair<std::string,std::string> MethodName;
    typedef std::map<MethodName, std::string> DisallowedMethods;
    DisallowedMethods disallowed;
    bool disallowAllV1Methods;

    // Agent name and address
    qpid::types::Variant::Map attrMap;
    std::string       name_address;
    std::string vendorNameKey;  // "." --> "_"
    std::string productNameKey; // "." --> "_"
    std::string instanceNameKey; // "." --> "_"

    // supported management protocol
    bool qmf1Support;
    bool qmf2Support;

    // Maximum # of objects allowed in a single V2 response
    // message.
    uint32_t maxReplyObjs;

    // list of objects that have been deleted, but have yet to be published
    // one final time.
    // Indexed by a string composed of the object's package and class name.
    // Protected by userLock.
    typedef std::map<std::string, DeletedObjectList> PendingDeletedObjsMap;
    PendingDeletedObjsMap pendingDeletedObjs;

#   define MA_BUFFER_SIZE 65536
    char inputBuffer[MA_BUFFER_SIZE];
    char outputBuffer[MA_BUFFER_SIZE];
    char eventBuffer[MA_BUFFER_SIZE];
    framing::ResizableBuffer msgBuffer;

    void writeData ();
    void periodicProcessing (void);
    void deleteObjectNowLH(const ObjectId& oid);
    void encodeHeader       (framing::Buffer& buf, uint8_t  opcode, uint32_t  seq = 0);
    bool checkHeader        (framing::Buffer& buf, uint8_t *opcode, uint32_t *seq);
    void sendBufferLH(framing::Buffer&             buf,
                      uint32_t                     length,
                      qpid::broker::Exchange::shared_ptr exchange,
                      const std::string&           routingKey);
    void sendBufferLH(framing::Buffer&             buf,
                      uint32_t                     length,
                      const std::string&           exchange,
                      const std::string&           routingKey);
    void sendBufferLH(const std::string&     data,
                      const std::string&     cid,
                      const qpid::types::Variant::Map& headers,
                      const std::string&     content_type,
                      qpid::broker::Exchange::shared_ptr exchange,
                      const std::string& routingKey,
                      uint64_t ttl_msec = 0);
    void sendBufferLH(const std::string& data,
                      const std::string& cid,
                      const qpid::types::Variant::Map& headers,
                      const std::string& content_type,
                      const std::string& exchange,
                      const std::string& routingKey,
                      uint64_t ttl_msec = 0);
    void moveNewObjectsLH();
    bool moveDeletedObjectsLH();

    bool authorizeAgentMessageLH(qpid::broker::Message& msg);
    void dispatchAgentCommandLH(qpid::broker::Message& msg, bool viaLocal=false);

    PackageMap::iterator findOrAddPackageLH(std::string name);
    void addClassLH(uint8_t                      kind,
                    PackageMap::iterator         pIter,
                    const std::string&           className,
                    uint8_t*                     md5Sum,
                    ManagementObject::writeSchemaCall_t schemaCall);
    void encodePackageIndication (framing::Buffer&     buf,
                                  PackageMap::iterator pIter);
    void encodeClassIndication (framing::Buffer&     buf,
                                const std::string packageName,
                                const struct SchemaClassKey key,
                                uint8_t kind);
    bool     bankInUse (uint32_t bank);
    uint32_t allocateNewBank ();
    uint32_t assignBankLH (uint32_t requestedPrefix);
    void deleteOrphanedAgentsLH();
    void sendCommandCompleteLH(const std::string& replyToKey, uint32_t sequence,
                              uint32_t code = 0, const std::string& text = "OK");
    void sendExceptionLH(const std::string& rte, const std::string& rtk, const std::string& cid, const std::string& text, uint32_t code=1, bool viaLocal=false);
    void handleBrokerRequestLH  (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handlePackageQueryLH   (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handlePackageIndLH     (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handleClassQueryLH     (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handleClassIndLH       (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handleSchemaRequestLH  (framing::Buffer& inBuffer, const std::string& replyToEx, const std::string& replyToKey, uint32_t sequence);
    void handleSchemaResponseLH (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handleAttachRequestLH  (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence, const qpid::broker::ConnectionToken* connToken);
    void handleGetQueryLH       (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence);
    void handleMethodRequestLH  (framing::Buffer& inBuffer, const std::string& replyToKey, uint32_t sequence, const qpid::broker::ConnectionToken* connToken);
    void handleGetQueryLH       (const std::string& body, const std::string& replyToEx, const std::string& replyToKey, const std::string& cid, bool viaLocal);
    void handleMethodRequestLH  (const std::string& body, const std::string& replyToEx, const std::string& replyToKey, const std::string& cid, const qpid::broker::ConnectionToken* connToken, bool viaLocal);
    void handleLocateRequestLH  (const std::string& body, const std::string& replyToEx, const std::string &replyToKey, const std::string& cid);


    size_t validateSchema(framing::Buffer&, uint8_t kind);
    size_t validateTableSchema(framing::Buffer&);
    size_t validateEventSchema(framing::Buffer&);
    ManagementObjectMap::iterator numericFind(const ObjectId& oid);

    std::string summarizeAgents();
    void debugSnapshot(const char* title);
};

void setManagementExecutionContext(const qpid::broker::ConnectionState*);
const qpid::broker::ConnectionState* getManagementExecutionContext();
}}

#endif  /*!_ManagementAgent_*/
