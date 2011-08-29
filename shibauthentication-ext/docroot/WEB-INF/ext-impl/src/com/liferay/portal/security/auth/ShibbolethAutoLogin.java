/*
 *    Copyright 2011 Johns Hopkins University

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package com.liferay.portal.security.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.kernel.util.StackTraceUtil;
import com.liferay.portal.model.User;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.PrefsPropsUtil;
import com.liferay.portal.util.PropsValues;

public class ShibbolethAutoLogin implements AutoLogin {

	private static Log _log = LogFactoryUtil.getLog(ShibbolethAutoLogin.class);
	String userEmail = "";

	public String[] login(HttpServletRequest req, HttpServletResponse res)
			throws AutoLoginException {

		String[] credentials = null;
		
		try {	
			long companyId = PortalUtil.getCompanyId(req);

			if (!PrefsPropsUtil.getBoolean(
					companyId, PropsKeys.SHIBBOLETH_AUTH_ENABLED,
					PropsValues.SHIBBOLETH_AUTH_ENABLED)) {

				return credentials;
			}
			userEmail = (String) req.getAttribute(PrefsPropsUtil.getString(companyId, PropsKeys.SHIBBOLETH_USER_HEADER,PropsValues.SHIBBOLETH_USER_HEADER));

			_log.info("User Login received:" + userEmail);

		if (userEmail.equals("") || userEmail.length() < 1) {
			_log.error("Invalid or missing user login information from Shibboleth");
			_log.error("Data returned from attribute:" + userEmail);
			return credentials;
		}

			credentials = new String[3];

			User user = UserLocalServiceUtil.getUserByEmailAddress(PortalUtil
					.getCompany(req).getCompanyId(), userEmail);

			credentials[0] = String.valueOf(user.getUserId());
			credentials[1] = user.getPassword();
			credentials[2] = Boolean.TRUE.toString();

			return credentials;

		} catch (NoSuchUserException e) {
			_log.error("No user found to match " + userEmail);
		} catch (Exception e) {
			_log.error(StackTraceUtil.getStackTrace(e));
			throw new AutoLoginException(e);
		}

		return credentials;
	}

}