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
package org.apache.qpid.test.unit.message;

import java.util.Map;

import javax.jms.Destination;
import javax.jms.JMSException;
import javax.jms.TemporaryQueue;
import javax.jms.Topic;
import javax.jms.TopicSubscriber;

import org.apache.qpid.AMQException;
import org.apache.qpid.client.AMQDestination;
import org.apache.qpid.client.AMQSession;
import org.apache.qpid.client.BasicMessageConsumer_0_8;
import org.apache.qpid.client.BasicMessageProducer_0_8;
import org.apache.qpid.client.failover.FailoverException;
import org.apache.qpid.client.message.AMQMessageDelegateFactory;
import org.apache.qpid.client.protocol.AMQProtocolHandler;
import org.apache.qpid.framing.AMQShortString;
import org.apache.qpid.framing.FieldTable;

public class TestAMQSession extends AMQSession<BasicMessageConsumer_0_8, BasicMessageProducer_0_8>
{

    public TestAMQSession()
    {
        super(null, 0, false, AUTO_ACKNOWLEDGE, null, 0, 0);
    }

    public void acknowledgeMessage(long deliveryTag, boolean multiple)
    {

    }

    public void sendQueueBind(AMQShortString queueName, AMQShortString routingKey, FieldTable arguments,
                              AMQShortString exchangeName, AMQDestination destination,
                              boolean nowait) throws AMQException, FailoverException
    {

    }

    public void sendClose(long timeout) throws AMQException, FailoverException
    {

    }

    public void sendCommit() throws AMQException, FailoverException
    {

    }

    public TopicSubscriber createDurableSubscriber(Topic topic, String name) throws JMSException
    {
        return null;
    }

    public void sendCreateQueue(AMQShortString name, boolean autoDelete, boolean durable, boolean exclusive, Map<String, Object> arguments) throws AMQException, FailoverException
    {

    }

    public TemporaryQueue createTemporaryQueue() throws JMSException
    {
        return null;
    }

    protected void sendRecover() throws AMQException, FailoverException
    {

    }

    public void rejectMessage(long deliveryTag, boolean requeue)
    {

    }

    public void releaseForRollback()
    {

    }

    public void sendRollback() throws AMQException, FailoverException
    {

    }

    public BasicMessageConsumer_0_8 createMessageConsumer(AMQDestination destination, int prefetchHigh, int prefetchLow, boolean noLocal, boolean exclusive, String selector, FieldTable arguments, boolean noConsume, boolean autoClose) throws JMSException
    {
        return null;
    }

    public boolean isQueueBound(AMQShortString exchangeName, AMQShortString queueName, AMQShortString routingKey) throws JMSException
    {
        return false;
    }

    public boolean isQueueBound(AMQDestination destination) throws JMSException
    {
        return false;
    }

    public void sendConsume(BasicMessageConsumer_0_8 consumer, AMQShortString queueName, AMQProtocolHandler protocolHandler, boolean nowait, String messageSelector, int tag) throws AMQException, FailoverException
    {

    }

    public BasicMessageProducer_0_8 createMessageProducer(Destination destination, boolean mandatory, boolean immediate, long producerId)
    {
        return null;
    }

    protected Long requestQueueDepth(AMQDestination amqd) throws AMQException, FailoverException
    {
        return null;
    }

    public void sendExchangeDeclare(AMQShortString name, AMQShortString type, AMQProtocolHandler protocolHandler, boolean nowait) throws AMQException, FailoverException
    {

    }

    public void sendQueueDeclare(AMQDestination amqd, AMQProtocolHandler protocolHandler,
                                 boolean nowait) throws AMQException, FailoverException
    {

    }

    public void sendQueueDelete(AMQShortString queueName) throws AMQException, FailoverException
    {

    }

    public void sendSuspendChannel(boolean suspend) throws AMQException, FailoverException
    {

    }

    protected boolean tagLE(long tag1, long tag2)
    {
        return false;
    }

    protected boolean updateRollbackMark(long current, long deliveryTag)
    {
        return false;
    }

    public AMQMessageDelegateFactory getMessageDelegateFactory()
    {
        return AMQMessageDelegateFactory.FACTORY_0_8;
    }

    protected Object getFailoverMutex()
    {
        return this;
    }

    public void checkNotClosed()
    {

    }

    public void sync()
    {
    }

    public void handleAddressBasedDestination(AMQDestination dest, 
                                              boolean isConsumer, 
                                              boolean noWait) throws AMQException
    {
        throw new UnsupportedOperationException("The new addressing based sytanx is "
                + "not supported for AMQP 0-8/0-9 versions");
    }

    @Override
    protected void flushAcknowledgments()
    {      
    }

    public boolean isQueueBound(String exchangeName, String queueName,
            String bindingKey, Map<String, Object> args) throws JMSException
    {
        return false;
    }

    @Override
    public AMQException getLastException()
    {
        return null;
    }
}
