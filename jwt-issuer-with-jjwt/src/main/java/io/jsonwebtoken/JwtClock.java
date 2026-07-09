/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.jsonwebtoken;

import java.util.Date;

import io.github.hiwepy.jwt.time.JwtTimeProvider;

import io.jsonwebtoken.Clock;

public class JwtClock implements Clock {

	 private JwtTimeProvider timeProvider = JwtTimeProvider.DEFAULT_TIME_PROVIDER;
	
	@Override
	public Date now() {
		long currentTimeMillis = this.getTimeProvider().now();
		return new Date(currentTimeMillis);
	}

	public JwtTimeProvider getTimeProvider() {
		return timeProvider;
	}

	public void setTimeProvider(JwtTimeProvider timeProvider) {
		this.timeProvider = timeProvider;
	}
	
}
