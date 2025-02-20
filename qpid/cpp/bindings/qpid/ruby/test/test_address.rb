#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

$:.unshift File.join(File.dirname(__FILE__), "..", "lib")

require 'test/unit'
require 'flexmock/test_unit'

require 'cqpid'
require 'qpid/address'

class TestAddress < Test::Unit::TestCase

  def test_constructor
    result = Qpid::Messaging::Address.new "name", "subject", {:foo => :bar}, "type"

    assert_equal "name", result.name
    assert_equal "subject", result.subject
    assert_equal "type", result._type
  end

end

