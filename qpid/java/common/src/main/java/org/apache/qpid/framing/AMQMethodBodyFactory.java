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
package org.apache.qpid.framing;

import org.apache.qpid.protocol.AMQVersionAwareProtocolSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.IOException;

public class AMQMethodBodyFactory implements BodyFactory
{
    private static final Logger _log = LoggerFactory.getLogger(AMQMethodBodyFactory.class);

    private final AMQVersionAwareProtocolSession _protocolSession;

    public AMQMethodBodyFactory(AMQVersionAwareProtocolSession protocolSession)
    {
        _protocolSession = protocolSession;
    }

    public AMQBody createBody(DataInputStream in, long bodySize) throws AMQFrameDecodingException, IOException
    {
        return _protocolSession.getMethodRegistry().convertToBody(in, bodySize);
    }
}
