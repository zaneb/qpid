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
package org.apache.qpid.server.queue;

import java.util.HashSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.qpid.AMQException;
import org.apache.qpid.framing.AMQShortString;
import org.apache.qpid.framing.FieldTable;
import org.apache.qpid.server.exchange.Exchange;

/**
 * When a queue is deleted, it should be deregistered from any
 * exchange it has been bound to. This class assists in this task,
 * by keeping track of all bindings for a given queue.
 */
class ExchangeBindings
{
    private static final FieldTable EMPTY_ARGUMENTS = new FieldTable();

    static class ExchangeBinding
    {
        private final Exchange _exchange;
        private final AMQShortString _routingKey;
        private final FieldTable _arguments;

        ExchangeBinding(AMQShortString routingKey, Exchange exchange)
        {
            this(routingKey, exchange,EMPTY_ARGUMENTS);
        }

        ExchangeBinding(AMQShortString routingKey, Exchange exchange, FieldTable arguments)
        {
            _routingKey = routingKey;
            _exchange = exchange;
            _arguments = arguments == null ? EMPTY_ARGUMENTS : arguments;
        }

        void unbind(AMQQueue queue) throws AMQException
        {
            _exchange.deregisterQueue(_routingKey, queue, _arguments);
        }

        public Exchange getExchange()
        {
            return _exchange;
        }

        public AMQShortString getRoutingKey()
        {
            return _routingKey;
        }

        public int hashCode()
        {
            return (_exchange == null ? 0 : _exchange.hashCode())
                   + (_routingKey == null ? 0 : _routingKey.hashCode())
                   + (_arguments == null ? 0 : _arguments.hashCode());
        }

        public boolean equals(Object o)
        {
            if (!(o instanceof ExchangeBinding))
            {
                return false;
            }
            ExchangeBinding eb = (ExchangeBinding) o;
            return _exchange.equals(eb._exchange)
                   && _routingKey.equals(eb._routingKey)
                   && _arguments.equals(eb._arguments);
        }
    }

    private final List<ExchangeBinding> _bindings = new CopyOnWriteArrayList<ExchangeBinding>();
    private final AMQQueue _queue;

    ExchangeBindings(AMQQueue queue)
    {
        _queue = queue;
    }

    /**
     * Adds the specified binding to those being tracked.
     * @param routingKey the routing key with which the queue whose bindings
     * are being tracked by the instance has been bound to the exchange
     * @param exchange the exchange bound to
     */
    void addBinding(AMQShortString routingKey, FieldTable arguments, Exchange exchange)
    {
        _bindings.add(new ExchangeBinding(routingKey, exchange, arguments));
    }


    public void remove(AMQShortString routingKey, FieldTable arguments, Exchange exchange)
    {
        _bindings.remove(new ExchangeBinding(routingKey, exchange, arguments));
    }


    /**
     * Deregisters this queue from any exchange it has been bound to
     */
    void deregister() throws AMQException
    {
        //remove duplicates at this point
        HashSet<ExchangeBinding> copy = new HashSet<ExchangeBinding>(_bindings);
        for (ExchangeBinding b : copy)
        {
            b.unbind(_queue);
        }
    }

    List<ExchangeBinding> getExchangeBindings()
    {
        return _bindings;
    }
}
