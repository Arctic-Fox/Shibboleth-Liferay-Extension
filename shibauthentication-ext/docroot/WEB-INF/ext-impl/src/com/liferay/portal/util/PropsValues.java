/**
 * Copyright (c) 2000-2011 Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.util;

import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.StringUtil;

/**
 * @author Brian Wing Shun Chan
 */
public class PropsValues {

	public static String[] ADMIN_DEFAULT_GROUP_NAMES = StringUtil.split(PropsUtil.get(PropsKeys.ADMIN_DEFAULT_GROUP_NAMES), StringPool.NEW_LINE);

	public static String[] ADMIN_DEFAULT_ROLE_NAMES = StringUtil.split(PropsUtil.get(PropsKeys.ADMIN_DEFAULT_ROLE_NAMES), StringPool.NEW_LINE);

	public static String[] ADMIN_DEFAULT_USER_GROUP_NAMES = StringUtil.split(PropsUtil.get(PropsKeys.ADMIN_DEFAULT_USER_GROUP_NAMES), StringPool.NEW_LINE);

	public static final String[] ADMIN_MAIL_HOST_NAMES = StringUtil.split(PropsUtil.get(PropsKeys.ADMIN_MAIL_HOST_NAMES), StringPool.NEW_LINE);

	public static final String[] ADMIN_RESERVED_EMAIL_ADDRESSES = StringUtil.split(PropsUtil.get(PropsKeys.ADMIN_RESERVED_EMAIL_ADDRESSES), StringPool.NEW_LINE);

	public static final String[] ADMIN_RESERVED_SCREEN_NAMES = StringUtil.split(PropsUtil.get(PropsKeys.ADMIN_RESERVED_SCREEN_NAMES), StringPool.NEW_LINE);

	public static final boolean ADMIN_SYNC_DEFAULT_ASSOCIATIONS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ADMIN_SYNC_DEFAULT_ASSOCIATIONS));

	public static final String ANNOUNCEMENTS_EMAIL_BODY = PropsUtil.get(PropsKeys.ANNOUNCEMENTS_EMAIL_BODY);

	public static final String ANNOUNCEMENTS_EMAIL_FROM_ADDRESS = PropsUtil.get(PropsKeys.ANNOUNCEMENTS_EMAIL_FROM_ADDRESS);

	public static final String ANNOUNCEMENTS_EMAIL_FROM_NAME = PropsUtil.get(PropsKeys.ANNOUNCEMENTS_EMAIL_FROM_NAME);

	public static final String ANNOUNCEMENTS_EMAIL_SUBJECT = PropsUtil.get(PropsKeys.ANNOUNCEMENTS_EMAIL_SUBJECT);

	public static final String ANNOUNCEMENTS_EMAIL_TO_ADDRESS = PropsUtil.get(PropsKeys.ANNOUNCEMENTS_EMAIL_TO_ADDRESS);

	public static final String ANNOUNCEMENTS_EMAIL_TO_NAME = PropsUtil.get(PropsKeys.ANNOUNCEMENTS_EMAIL_TO_NAME);

	public static final int ANNOUNCEMENTS_ENTRY_CHECK_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.ANNOUNCEMENTS_ENTRY_CHECK_INTERVAL));

	public static final String[] APPLICATION_SHUTDOWN_EVENTS = PropsUtil.getArray(PropsKeys.APPLICATION_SHUTDOWN_EVENTS);

	public static final String[] APPLICATION_STARTUP_EVENTS = PropsUtil.getArray(PropsKeys.APPLICATION_STARTUP_EVENTS);

	public static final String[] ASSET_CATEGORIES_PROPERTIES_DEFAULT = PropsUtil.getArray(PropsKeys.ASSET_CATEGORIES_PROPERTIES_DEFAULT);

	public static final boolean ASSET_CATEGORIES_SEARCH_HIERARCHICAL = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ASSET_CATEGORIES_SEARCH_HIERARCHICAL));

	public static final boolean ASSET_ENTRY_INCREMENT_VIEW_COUNTER_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ASSET_ENTRY_INCREMENT_VIEW_COUNTER_ENABLED));

	public static final String ASSET_ENTRY_VALIDATOR = PropsUtil.get(PropsKeys.ASSET_ENTRY_VALIDATOR);

	public static final int ASSET_FILTER_SEARCH_LIMIT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.ASSET_FILTER_SEARCH_LIMIT));

	public static final String[] ASSET_PUBLISHER_DISPLAY_STYLES = PropsUtil.getArray(PropsKeys.ASSET_PUBLISHER_DISPLAY_STYLES);

	public static final String[] ASSET_TAG_PROPERTIES_DEFAULT = PropsUtil.getArray(PropsKeys.ASSET_TAG_PROPERTIES_DEFAULT);

	public static final String ASSET_VOCABULARY_DEFAULT = PropsUtil.get(PropsKeys.ASSET_VOCABULARY_DEFAULT);

	public static final String[] AUTH_FAILURE = PropsUtil.getArray(PropsKeys.AUTH_FAILURE);

	public static boolean AUTH_FORWARD_BY_LAST_PATH = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTH_FORWARD_BY_LAST_PATH));

	public static final boolean AUTH_FORWARD_BY_REDIRECT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTH_FORWARD_BY_REDIRECT));

	public static final String AUTH_LOGIN_COMMUNITY_URL = PropsUtil.get(PropsKeys.AUTH_LOGIN_COMMUNITY_URL);

	public static final String AUTH_LOGIN_PORTLET_NAME = PropsUtil.get(PropsKeys.AUTH_LOGIN_PORTLET_NAME);

	public static final String AUTH_LOGIN_URL = PropsUtil.get(PropsKeys.AUTH_LOGIN_URL);

	public static final String[] AUTH_MAX_FAILURES = PropsUtil.getArray(PropsKeys.AUTH_MAX_FAILURES);

	public static final boolean AUTH_PIPELINE_ENABLE_LIFERAY_CHECK = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTH_PIPELINE_ENABLE_LIFERAY_CHECK));

	public static final String[] AUTH_PIPELINE_POST = PropsUtil.getArray(PropsKeys.AUTH_PIPELINE_POST);

	public static final String[] AUTH_PIPELINE_PRE = PropsUtil.getArray(PropsKeys.AUTH_PIPELINE_PRE);

	public static final boolean AUTH_TOKEN_CHECK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTH_TOKEN_CHECK_ENABLED));

	public static final String AUTH_TOKEN_IMPL = PropsUtil.get(PropsKeys.AUTH_TOKEN_IMPL);

	public static final String AUTH_TOKEN_SHARED_SECRET = PropsUtil.get(PropsKeys.AUTH_TOKEN_SHARED_SECRET);

	public static final int AUTO_DEPLOY_BLACKLIST_THRESHOLD = GetterUtil.getInteger(PropsUtil.get(PropsKeys.AUTO_DEPLOY_BLACKLIST_THRESHOLD));

	public static final boolean AUTO_DEPLOY_CUSTOM_PORTLET_XML = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTO_DEPLOY_CUSTOM_PORTLET_XML));

	public static final String AUTO_DEPLOY_DEFAULT_DEST_DIR = PropsUtil.get(PropsKeys.AUTO_DEPLOY_DEFAULT_DEST_DIR);

	public static final String AUTO_DEPLOY_DEPLOY_DIR = PropsUtil.get(PropsKeys.AUTO_DEPLOY_DEPLOY_DIR);

	public static final String AUTO_DEPLOY_DEST_DIR = PropsUtil.get(PropsKeys.AUTO_DEPLOY_DEST_DIR);

	public static final boolean AUTO_DEPLOY_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTO_DEPLOY_ENABLED));

	public static final int AUTO_DEPLOY_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.AUTO_DEPLOY_INTERVAL));

	public static final String AUTO_DEPLOY_JBOSS_PREFIX = PropsUtil.get(PropsKeys.AUTO_DEPLOY_JBOSS_PREFIX);

	public static final String AUTO_DEPLOY_TOMCAT_CONF_DIR = PropsUtil.get(PropsKeys.AUTO_DEPLOY_TOMCAT_CONF_DIR);

	public static final String AUTO_DEPLOY_TOMCAT_DEST_DIR = PropsUtil.get(PropsKeys.AUTO_DEPLOY_TOMCAT_DEST_DIR);

	public static final String AUTO_DEPLOY_TOMCAT_LIB_DIR = PropsUtil.get(PropsKeys.AUTO_DEPLOY_TOMCAT_LIB_DIR);

	public static final boolean AUTO_DEPLOY_UNPACK_WAR = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.AUTO_DEPLOY_UNPACK_WAR));

	public static final String[] AUTO_LOGIN_HOOKS = PropsUtil.getArray(PropsKeys.AUTO_LOGIN_HOOKS);

	public static final boolean BASIC_AUTH_PASSWORD_REQUIRED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BASIC_AUTH_PASSWORD_REQUIRED));

	public static final boolean BLOGS_ENTRY_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BLOGS_ENTRY_COMMENTS_ENABLED));

	public static final boolean BLOGS_ENTRY_PREVIOUS_AND_NEXT_NAVIGATION_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BLOGS_ENTRY_PREVIOUS_AND_NEXT_NAVIGATION_ENABLED));

	public static final int BLOGS_LINKBACK_EXCERPT_LENGTH = GetterUtil.getInteger(PropsUtil.get(PropsKeys.BLOGS_LINKBACK_EXCERPT_LENGTH));

	public static final int BLOGS_PAGE_ABSTRACT_LENGTH = GetterUtil.getInteger(PropsUtil.get(PropsKeys.BLOGS_PAGE_ABSTRACT_LENGTH));

	public static final boolean BLOGS_PING_GOOGLE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BLOGS_PING_GOOGLE_ENABLED));

	public static final boolean BLOGS_PINGBACK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BLOGS_PINGBACK_ENABLED));

	public static final boolean BLOGS_TRACKBACK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BLOGS_TRACKBACK_ENABLED));

	public static final boolean BREADCRUMB_SHOW_GUEST_GROUP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BREADCRUMB_SHOW_GUEST_GROUP));

	public static final boolean BREADCRUMB_SHOW_PARENT_GROUPS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.BREADCRUMB_SHOW_PARENT_GROUPS));

	public static final String BROWSER_LAUNCHER_URL = PropsUtil.get(PropsKeys.BROWSER_LAUNCHER_URL);

	public static final int CALENDAR_EVENT_CHECK_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.CALENDAR_EVENT_CHECK_INTERVAL));

	public static final boolean CALENDAR_EVENT_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CALENDAR_EVENT_COMMENTS_ENABLED));

	public static boolean CAPTCHA_CHECK_PORTAL_CREATE_ACCOUNT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CAPTCHA_CHECK_PORTAL_CREATE_ACCOUNT));

	public static final boolean CAPTCHA_CHECK_PORTAL_SEND_PASSWORD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CAPTCHA_CHECK_PORTAL_SEND_PASSWORD));

	public static final boolean CAPTCHA_CHECK_PORTLET_MESSAGE_BOARDS_EDIT_CATEGORY = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CAPTCHA_CHECK_PORTLET_MESSAGE_BOARDS_EDIT_CATEGORY));

	public static final boolean CAPTCHA_CHECK_PORTLET_MESSAGE_BOARDS_EDIT_MESSAGE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CAPTCHA_CHECK_PORTLET_MESSAGE_BOARDS_EDIT_MESSAGE));

	public static final String CAPTCHA_ENGINE_IMPL = PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_IMPL);

	public static final String CAPTCHA_ENGINE_RECAPTCHA_KEY_PRIVATE = PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_RECAPTCHA_KEY_PRIVATE);

	public static final String CAPTCHA_ENGINE_RECAPTCHA_KEY_PUBLIC = PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_RECAPTCHA_KEY_PUBLIC);

	public static final String CAPTCHA_ENGINE_RECAPTCHA_URL_NOSCRIPT = PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_RECAPTCHA_URL_NOSCRIPT);

	public static final String CAPTCHA_ENGINE_RECAPTCHA_URL_SCRIPT = PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_RECAPTCHA_URL_SCRIPT);

	public static final String CAPTCHA_ENGINE_RECAPTCHA_URL_VERIFY = PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_RECAPTCHA_URL_VERIFY);

	public static final String[] CAPTCHA_ENGINE_SIMPLECAPTCHA_BACKGROUND_PRODUCERS = PropsUtil.getArray(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_BACKGROUND_PRODUCERS);

	public static final String[] CAPTCHA_ENGINE_SIMPLECAPTCHA_GIMPY_RENDERERS = PropsUtil.getArray(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_GIMPY_RENDERERS);

	public static final int CAPTCHA_ENGINE_SIMPLECAPTCHA_HEIGHT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_HEIGHT));

	public static final String[] CAPTCHA_ENGINE_SIMPLECAPTCHA_NOISE_PRODUCERS = PropsUtil.getArray(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_NOISE_PRODUCERS);

	public static final String[] CAPTCHA_ENGINE_SIMPLECAPTCHA_TEXT_PRODUCERS = PropsUtil.getArray(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_TEXT_PRODUCERS);

	public static final int CAPTCHA_ENGINE_SIMPLECAPTCHA_WIDTH = GetterUtil.getInteger(PropsUtil.get(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_WIDTH));

	public static final String[] CAPTCHA_ENGINE_SIMPLECAPTCHA_WORD_RENDERERS = PropsUtil.getArray(PropsKeys.CAPTCHA_ENGINE_SIMPLECAPTCHA_WORD_RENDERERS);

	public static final int CAPTCHA_MAX_CHALLENGES = GetterUtil.getInteger(PropsUtil.get(PropsKeys.CAPTCHA_MAX_CHALLENGES));

	public static final boolean CAS_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CAS_AUTH_ENABLED));

	public static final boolean CAS_IMPORT_FROM_LDAP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CAS_IMPORT_FROM_LDAP));

	public static final String CAS_LOGIN_URL = PropsUtil.get(PropsKeys.CAS_LOGIN_URL);

	public static final String CAS_LOGOUT_URL = PropsUtil.get(PropsKeys.CAS_LOGOUT_URL);

	public static final String CAS_SERVER_NAME = PropsUtil.get(PropsKeys.CAS_SERVER_NAME);

	public static final String CAS_SERVER_URL = PropsUtil.get(PropsKeys.CAS_SERVER_URL);

	public static final String CAS_SERVICE_URL = PropsUtil.get(PropsKeys.CAS_SERVICE_URL);

	public static final String CDN_HOST_HTTP = PropsUtil.get(PropsKeys.CDN_HOST_HTTP);

	public static final String CDN_HOST_HTTPS = PropsUtil.get(PropsKeys.CDN_HOST_HTTPS);

	public static final boolean CLUSTER_EXECUTOR_DEBUG_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CLUSTER_EXECUTOR_DEBUG_ENABLED));

	public static final String CLUSTER_LINK_AUTODETECT_ADDRESS = PropsUtil.get(PropsKeys.CLUSTER_LINK_AUTODETECT_ADDRESS);

	public static final String[] CLUSTER_LINK_CHANNEL_SYSTEM_PROPERTIES = PropsUtil.getArray(PropsKeys.CLUSTER_LINK_CHANNEL_SYSTEM_PROPERTIES);

	public static final boolean CLUSTER_LINK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.CLUSTER_LINK_ENABLED));

	public static final String CMIS_CREDENTIALS_PASSWORD = PropsUtil.get(PropsKeys.CMIS_CREDENTIALS_PASSWORD);

	public static final String CMIS_CREDENTIALS_USERNAME = PropsUtil.get(PropsKeys.CMIS_CREDENTIALS_USERNAME);

	public static final String CMIS_REPOSITORY_URL = PropsUtil.get(PropsKeys.CMIS_REPOSITORY_URL);

	public static final String CMIS_REPOSITORY_VERSION = PropsUtil.get(PropsKeys.CMIS_REPOSITORY_VERSION);

	public static final String CMIS_SYSTEM_ROOT_DIR = PropsUtil.get(PropsKeys.CMIS_SYSTEM_ROOT_DIR);

	public static final boolean COMBO_CHECK_TIMESTAMP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMBO_CHECK_TIMESTAMP));

	public static final boolean COMMUNITIES_CONTROL_PANEL_MEMBERS_VISIBLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMMUNITIES_CONTROL_PANEL_MEMBERS_VISIBLE));

	public static final String COMPANY_DEFAULT_HOME_URL = PropsUtil.get(PropsKeys.COMPANY_DEFAULT_HOME_URL);

	public static final String COMPANY_DEFAULT_WEB_ID = PropsUtil.get(PropsKeys.COMPANY_DEFAULT_WEB_ID);

	public static final boolean COMPANY_LOGIN_PREPOPULATE_DOMAIN = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_LOGIN_PREPOPULATE_DOMAIN));

	public static final boolean COMPANY_SECURITY_AUTH_REQUIRES_HTTPS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_AUTH_REQUIRES_HTTPS));

	public static final String COMPANY_SECURITY_AUTH_TYPE = PropsUtil.get(PropsKeys.COMPANY_SECURITY_AUTH_TYPE);

	public static final boolean COMPANY_SECURITY_AUTO_LOGIN = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_AUTO_LOGIN));

	public static final int COMPANY_SECURITY_AUTO_LOGIN_MAX_AGE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.COMPANY_SECURITY_AUTO_LOGIN_MAX_AGE), CookieKeys.MAX_AGE);

	public static final boolean COMPANY_SECURITY_COMMUNITY_LOGO = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_COMMUNITY_LOGO));

	public static final boolean COMPANY_SECURITY_SEND_PASSWORD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_SEND_PASSWORD));

	public static final boolean COMPANY_SECURITY_SEND_PASSWORD_RESET_LINK = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_SEND_PASSWORD_RESET_LINK));

	public static final boolean COMPANY_SECURITY_STRANGERS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_STRANGERS));

	public static final String COMPANY_SECURITY_STRANGERS_URL = PropsUtil.get(PropsKeys.COMPANY_SECURITY_STRANGERS_URL);

	public static final boolean COMPANY_SECURITY_STRANGERS_VERIFY = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_STRANGERS_VERIFY));

	public static final boolean COMPANY_SECURITY_STRANGERS_WITH_MX = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.COMPANY_SECURITY_STRANGERS_WITH_MX));

	public static final String[] COMPANY_SETTINGS_FORM_CONFIGURATION = PropsUtil.getArray(PropsKeys.COMPANY_SETTINGS_FORM_CONFIGURATION);

	public static final String[] COMPANY_SETTINGS_FORM_IDENTIFICATION = PropsUtil.getArray(PropsKeys.COMPANY_SETTINGS_FORM_IDENTIFICATION);

	public static final String[] COMPANY_SETTINGS_FORM_MISCELLANEOUS = PropsUtil.getArray(PropsKeys.COMPANY_SETTINGS_FORM_MISCELLANEOUS);

	public static final String CONTROL_PANEL_DEFAULT_ENTRY_CLASS = PropsUtil.get(PropsKeys.CONTROL_PANEL_DEFAULT_ENTRY_CLASS);

	public static final String CONTROL_PANEL_LAYOUT_FRIENDLY_URL = PropsUtil.get(PropsKeys.CONTROL_PANEL_LAYOUT_FRIENDLY_URL);

	public static final String CONTROL_PANEL_LAYOUT_NAME = PropsUtil.get(PropsKeys.CONTROL_PANEL_LAYOUT_NAME);

	public static final String CONTROL_PANEL_LAYOUT_REGULAR_THEME_ID = PropsUtil.get(PropsKeys.CONTROL_PANEL_LAYOUT_REGULAR_THEME_ID);

	public static final int CONTROL_PANEL_NAVIGATION_MAX_COMMUNITIES = GetterUtil.getInteger(PropsUtil.get(PropsKeys.CONTROL_PANEL_NAVIGATION_MAX_COMMUNITIES));

	public static final int CONTROL_PANEL_NAVIGATION_MAX_ORGANIZATIONS = GetterUtil.getInteger(PropsUtil.get(PropsKeys.CONTROL_PANEL_NAVIGATION_MAX_ORGANIZATIONS));

	public static String[] CONVERT_PROCESSES = PropsUtil.getArray(PropsKeys.CONVERT_PROCESSES);

	public static final int COUNTER_INCREMENT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.COUNTER_INCREMENT));

	public static final String CUSTOM_SQL_FUNCTION_ISNOTNULL = PropsUtil.get(PropsKeys.CUSTOM_SQL_FUNCTION_ISNOTNULL);

	public static final String CUSTOM_SQL_FUNCTION_ISNULL = PropsUtil.get(PropsKeys.CUSTOM_SQL_FUNCTION_ISNULL);

	public static final String DATABASE_MYSQL_ENGINE = PropsUtil.get(PropsKeys.DATABASE_MYSQL_ENGINE);

	public static final String DEFAULT_ADMIN_EMAIL_ADDRESS_PREFIX = PropsUtil.get(PropsKeys.DEFAULT_ADMIN_EMAIL_ADDRESS_PREFIX);

	public static final String DEFAULT_ADMIN_FIRST_NAME = PropsUtil.get(PropsKeys.DEFAULT_ADMIN_FIRST_NAME);

	public static final String DEFAULT_ADMIN_LAST_NAME = PropsUtil.get(PropsKeys.DEFAULT_ADMIN_LAST_NAME);

	public static final String DEFAULT_ADMIN_MIDDLE_NAME = PropsUtil.get(PropsKeys.DEFAULT_ADMIN_MIDDLE_NAME);

	public static final String DEFAULT_ADMIN_PASSWORD = PropsUtil.get(PropsKeys.DEFAULT_ADMIN_PASSWORD);

	public static final String DEFAULT_ADMIN_SCREEN_NAME = PropsUtil.get(PropsKeys.DEFAULT_ADMIN_SCREEN_NAME);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_COLUMN = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_COLUMN);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_FRIENDLY_URL = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_FRIENDLY_URL);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_NAME = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_NAME);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_REGULAR_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_REGULAR_COLOR_SCHEME_ID);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_REGULAR_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_REGULAR_THEME_ID);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_TEMPLATE_ID = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_TEMPLATE_ID);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_WAP_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_WAP_COLOR_SCHEME_ID);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_WAP_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUT_WAP_THEME_ID);

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUTS_LAR = PropsUtil.get(PropsKeys.DEFAULT_GUEST_PUBLIC_LAYOUTS_LAR);

	public static String DEFAULT_LANDING_PAGE_PATH = PropsUtil.get(PropsKeys.DEFAULT_LANDING_PAGE_PATH);

	public static final String DEFAULT_LAYOUT_TEMPLATE_ID = PropsUtil.get(PropsKeys.DEFAULT_LAYOUT_TEMPLATE_ID);

	public static final String DEFAULT_LOGOUT_PAGE_PATH = PropsUtil.get(PropsKeys.DEFAULT_LOGOUT_PAGE_PATH);

	public static final String DEFAULT_REGULAR_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_REGULAR_COLOR_SCHEME_ID);

	public static final String DEFAULT_REGULAR_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_REGULAR_THEME_ID);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_COLUMN = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_COLUMN);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_FRIENDLY_URL = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_FRIENDLY_URL);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_NAME = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_NAME);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_REGULAR_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_REGULAR_COLOR_SCHEME_ID);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_REGULAR_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_REGULAR_THEME_ID);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_TEMPLATE_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_TEMPLATE_ID);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_WAP_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_WAP_COLOR_SCHEME_ID);

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_WAP_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUT_WAP_THEME_ID);

	public static final String DEFAULT_USER_PRIVATE_LAYOUTS_LAR = PropsUtil.get(PropsKeys.DEFAULT_USER_PRIVATE_LAYOUTS_LAR);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_COLUMN = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_COLUMN);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_FRIENDLY_URL = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_FRIENDLY_URL);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_NAME = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_NAME);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_REGULAR_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_REGULAR_COLOR_SCHEME_ID);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_REGULAR_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_REGULAR_THEME_ID);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_TEMPLATE_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_TEMPLATE_ID);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_WAP_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_WAP_COLOR_SCHEME_ID);

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_WAP_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUT_WAP_THEME_ID);

	public static final String DEFAULT_USER_PUBLIC_LAYOUTS_LAR = PropsUtil.get(PropsKeys.DEFAULT_USER_PUBLIC_LAYOUTS_LAR);

	public static final String DEFAULT_WAP_COLOR_SCHEME_ID = PropsUtil.get(PropsKeys.DEFAULT_WAP_COLOR_SCHEME_ID);

	public static final String DEFAULT_WAP_THEME_ID = PropsUtil.get(PropsKeys.DEFAULT_WAP_THEME_ID);

	public static final String DISCUSSION_THREAD_VIEW = PropsUtil.get(PropsKeys.DISCUSSION_THREAD_VIEW);

	public static final String[] DL_COMPARABLE_FILE_EXTENSIONS = PropsUtil.getArray(PropsKeys.DL_COMPARABLE_FILE_EXTENSIONS);

	public static final boolean DL_FILE_ENTRY_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_FILE_ENTRY_COMMENTS_ENABLED));

	public static final boolean DL_FILE_ENTRY_READ_COUNT_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_FILE_ENTRY_READ_COUNT_ENABLED));

	public static final String[] DL_FILE_EXTENSIONS = PropsUtil.getArray(PropsKeys.DL_FILE_EXTENSIONS);

	public static final boolean DL_FILE_EXTENSIONS_STRICT_CHECK = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_FILE_EXTENSIONS_STRICT_CHECK));

	public static final long DL_FILE_INDEXING_MAX_SIZE = GetterUtil.getLong(PropsUtil.get(PropsKeys.DL_FILE_INDEXING_MAX_SIZE));

	public static final long DL_FILE_MAX_SIZE = GetterUtil.getLong(PropsUtil.get(PropsKeys.DL_FILE_MAX_SIZE));

	public static final boolean DL_FILE_RANK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_FILE_RANK_ENABLED));

	public static String DL_HOOK_IMPL = PropsUtil.get(PropsKeys.DL_HOOK_IMPL);

	public static final int DL_HOOK_JCR_FETCH_DELAY = GetterUtil.getInteger(PropsUtil.get(PropsKeys.DL_HOOK_JCR_FETCH_DELAY));

	public static final int DL_HOOK_JCR_FETCH_MAX_FAILURES = GetterUtil.getInteger(PropsUtil.get(PropsKeys.DL_HOOK_JCR_FETCH_MAX_FAILURES));

	public static final boolean DL_HOOK_JCR_MOVE_VERSION_LABELS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_HOOK_JCR_MOVE_VERSION_LABELS));

	public static final boolean DL_LAYOUTS_SYNC_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_LAYOUTS_SYNC_ENABLED));

	public static final boolean DL_PUBLISH_TO_LIVE_BY_DEFAULT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_PUBLISH_TO_LIVE_BY_DEFAULT));

	public static boolean DL_WEBDAV_HOLD_LOCK = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_WEBDAV_HOLD_LOCK));

	public static boolean DL_WEBDAV_SAVE_TO_SINGLE_VERSION = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.DL_WEBDAV_SAVE_TO_SINGLE_VERSION));

	public static final String[] DOCKBAR_ADD_PORTLETS = PropsUtil.getArray(PropsKeys.DOCKBAR_ADD_PORTLETS);

	public static final String EDITOR_WYSIWYG_DEFAULT = PropsUtil.get(PropsKeys.EDITOR_WYSIWYG_DEFAULT);

	public static final boolean EHCACHE_BLOCKING_CACHE_ALLOWED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.EHCACHE_BLOCKING_CACHE_ALLOWED));

	public static final String EHCACHE_BOOTSTRAP_CACHE_LOADER_FACTORY = PropsUtil.get(PropsKeys.EHCACHE_BOOTSTRAP_CACHE_LOADER_FACTORY);

	public static final String EHCACHE_CACHE_EVENT_LISTENER_FACTORY = PropsUtil.get(PropsKeys.EHCACHE_CACHE_EVENT_LISTENER_FACTORY);

	public static final String EHCACHE_CACHE_MANAGER_PEER_PROVIDER_FACTORY = PropsUtil.get(PropsKeys.EHCACHE_CACHE_MANAGER_PEER_PROVIDER_FACTORY);

	public static final boolean EHCACHE_PORTAL_CACHE_MANAGER_JMX_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.EHCACHE_PORTAL_CACHE_MANAGER_JMX_ENABLED));

	public static final boolean EHCACHE_STATISTICS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.EHCACHE_STATISTICS_ENABLED));

	public static final String FACEBOOK_CONNECT_APP_ID = PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_APP_ID);

	public static final String FACEBOOK_CONNECT_APP_SECRET = PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_APP_SECRET);

	public static final boolean FACEBOOK_CONNECT_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_AUTH_ENABLED));

	public static final String FACEBOOK_CONNECT_GRAPH_URL = PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_GRAPH_URL);

	public static final String FACEBOOK_CONNECT_OAUTH_AUTH_URL = PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_OAUTH_AUTH_URL);

	public static final String FACEBOOK_CONNECT_OAUTH_REDIRECT_URL = PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_OAUTH_REDIRECT_URL);

	public static final String FACEBOOK_CONNECT_OAUTH_TOKEN_URL = PropsUtil.get(PropsKeys.FACEBOOK_CONNECT_OAUTH_TOKEN_URL);

	public static final String[] FIELD_EDITABLE_COM_LIFERAY_PORTAL_MODEL_USER_EMAILADDRESS = PropsUtil.getArray(PropsKeys.FIELD_EDITABLE_COM_LIFERAY_PORTAL_MODEL_USER_EMAILADDRESS);

	public static final String[] FIELD_EDITABLE_COM_LIFERAY_PORTAL_MODEL_USER_SCREENNAME = PropsUtil.getArray(PropsKeys.FIELD_EDITABLE_COM_LIFERAY_PORTAL_MODEL_USER_SCREENNAME);

	public static boolean FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_CONTACT_BIRTHDAY = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_CONTACT_BIRTHDAY));

	public static boolean FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_CONTACT_MALE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_CONTACT_MALE));

	public static boolean FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_ORGANIZATION_STATUS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_ORGANIZATION_STATUS));

	public static final boolean FLAGS_GUEST_USERS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.FLAGS_GUEST_USERS_ENABLED));

	public static final String[] FLAGS_REASONS = PropsUtil.getArray(PropsKeys.FLAGS_REASONS);

	public static final String FREEMARKER_ENGINE_CACHE_STORAGE = PropsUtil.get(PropsKeys.FREEMARKER_ENGINE_CACHE_STORAGE);

	public static final boolean FREEMARKER_ENGINE_LOCALIZED_LOOKUP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.FREEMARKER_ENGINE_LOCALIZED_LOOKUP));

	public static final String FREEMARKER_ENGINE_MACRO_LIBRARY = PropsUtil.get(PropsKeys.FREEMARKER_ENGINE_MACRO_LIBRARY);

	public static final int FREEMARKER_ENGINE_MODIFICATION_CHECK_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.FREEMARKER_ENGINE_MODIFICATION_CHECK_INTERVAL));

	public static final String FREEMARKER_ENGINE_TEMPLATE_EXCEPTION_HANDLER = PropsUtil.get(PropsKeys.FREEMARKER_ENGINE_TEMPLATE_EXCEPTION_HANDLER);

	public static final String[] FREEMARKER_ENGINE_TEMPLATE_LOADERS = PropsUtil.getArray(PropsKeys.FREEMARKER_ENGINE_TEMPLATE_LOADERS);

	public static final String[] GLOBAL_SHUTDOWN_EVENTS = PropsUtil.getArray(PropsKeys.GLOBAL_SHUTDOWN_EVENTS);

	public static final String[] GLOBAL_STARTUP_EVENTS = PropsUtil.getArray(PropsKeys.GLOBAL_STARTUP_EVENTS);

	public static final String GOOGLE_GADGET_SERVLET_MAPPING = PropsUtil.get(PropsKeys.GOOGLE_GADGET_SERVLET_MAPPING);

	public static final String HIBERNATE_DIALECT = PropsUtil.get(PropsKeys.HIBERNATE_DIALECT);

	public static final boolean HIBERNATE_GENERATE_STATISTICS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.HIBERNATE_GENERATE_STATISTICS));

	public static final int HIBERNATE_JDBC_BATCH_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.HIBERNATE_JDBC_BATCH_SIZE));

	public static final boolean HOT_UNDEPLOY_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.HOT_UNDEPLOY_ENABLED));

	public static final int HOT_UNDEPLOY_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.HOT_UNDEPLOY_INTERVAL));

	public static final boolean HOT_UNDEPLOY_ON_REDEPLOY = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.HOT_UNDEPLOY_ON_REDEPLOY));

	public static final String IFRAME_PASSWORD_PASSWORD_TOKEN_ROLE = PropsUtil.get(PropsKeys.IFRAME_PASSWORD_PASSWORD_TOKEN_ROLE);

	public static final int IG_IMAGE_CUSTOM_1_MAX_DIMENSION = GetterUtil.getInteger(PropsUtil.get(PropsKeys.IG_IMAGE_CUSTOM_1_MAX_DIMENSION));

	public static final int IG_IMAGE_CUSTOM_2_MAX_DIMENSION = GetterUtil.getInteger(PropsUtil.get(PropsKeys.IG_IMAGE_CUSTOM_2_MAX_DIMENSION));

	public static final String[] IG_IMAGE_EXTENSIONS = PropsUtil.getArray(PropsKeys.IG_IMAGE_EXTENSIONS);

	public static final int IG_IMAGE_MAX_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.IG_IMAGE_MAX_SIZE));

	public static final int IG_IMAGE_THUMBNAIL_MAX_DIMENSION = GetterUtil.getInteger(PropsUtil.get(PropsKeys.IG_IMAGE_THUMBNAIL_MAX_DIMENSION));

	public static final boolean IG_PUBLISH_TO_LIVE_BY_DEFAULT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.IG_PUBLISH_TO_LIVE_BY_DEFAULT));

	public static final String IMAGE_HOOK_FILE_SYSTEM_ROOT_DIR = PropsUtil.get(PropsKeys.IMAGE_HOOK_FILE_SYSTEM_ROOT_DIR);

	public static String IMAGE_HOOK_IMPL = PropsUtil.get(PropsKeys.IMAGE_HOOK_IMPL);

	public static final int INDEX_ON_STARTUP_DELAY = GetterUtil.getInteger(PropsUtil.get(PropsKeys.INDEX_ON_STARTUP_DELAY));

	public static final boolean INDEX_ON_UPGRADE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.INDEX_ON_UPGRADE));

	public static boolean INDEX_READ_ONLY = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.INDEX_READ_ONLY));

	public static final boolean JAVASCRIPT_BAREBONE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JAVASCRIPT_BAREBONE_ENABLED));

	public static final String[] JAVASCRIPT_BUNDLE_IDS = PropsUtil.getArray(PropsKeys.JAVASCRIPT_BUNDLE_IDS);

	public static boolean JAVASCRIPT_FAST_LOAD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JAVASCRIPT_FAST_LOAD));

	public static final boolean JAVASCRIPT_LOG_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JAVASCRIPT_LOG_ENABLED));

	public static final String JDBC_DEFAULT_LIFERAY_POOL_PROVIDER = PropsUtil.get(PropsKeys.JDBC_DEFAULT_LIFERAY_POOL_PROVIDER);

	public static final int JOURNAL_ARTICLE_CHECK_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.JOURNAL_ARTICLE_CHECK_INTERVAL));

	public static final boolean JOURNAL_ARTICLE_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_ARTICLE_COMMENTS_ENABLED));

	public static final String[] JOURNAL_ARTICLE_CUSTOM_TOKENS = PropsUtil.getArray(PropsKeys.JOURNAL_ARTICLE_CUSTOM_TOKENS);

	public static final boolean JOURNAL_ARTICLE_FORCE_AUTOGENERATE_ID = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_ARTICLE_FORCE_AUTOGENERATE_ID));

	public static final boolean JOURNAL_ARTICLE_VIEW_PERMISSION_CHECK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_ARTICLE_VIEW_PERMISSION_CHECK_ENABLED));

	public static final boolean JOURNAL_CONTENT_SEARCH_SHOW_LISTED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_CONTENT_SEARCH_SHOW_LISTED));

	public static final String JOURNAL_ERROR_TEMPLATE_FREEMARKER = PropsUtil.get(PropsKeys.JOURNAL_ERROR_TEMPLATE_FREEMARKER);

	public static final String JOURNAL_ERROR_TEMPLATE_VELOCITY = PropsUtil.get(PropsKeys.JOURNAL_ERROR_TEMPLATE_VELOCITY);

	public static final String JOURNAL_ERROR_TEMPLATE_XSL = PropsUtil.get(PropsKeys.JOURNAL_ERROR_TEMPLATE_XSL);

	public static final boolean JOURNAL_FEED_FORCE_AUTOGENERATE_ID = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_FEED_FORCE_AUTOGENERATE_ID));

	public static final String JOURNAL_LAR_CREATION_STRATEGY = PropsUtil.get(PropsKeys.JOURNAL_LAR_CREATION_STRATEGY);

	public static final boolean JOURNAL_PUBLISH_TO_LIVE_BY_DEFAULT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_PUBLISH_TO_LIVE_BY_DEFAULT));

	public static final boolean JOURNAL_STRUCTURE_FORCE_AUTOGENERATE_ID = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_STRUCTURE_FORCE_AUTOGENERATE_ID));

	public static final boolean JOURNAL_TEMPLATE_FORCE_AUTOGENERATE_ID = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.JOURNAL_TEMPLATE_FORCE_AUTOGENERATE_ID));

	public static final String[] JOURNAL_TEMPLATE_FREEMARKER_RESTRICTED_VARIABLES = PropsUtil.getArray(PropsKeys.JOURNAL_TEMPLATE_FREEMARKER_RESTRICTED_VARIABLES);

	public static final String[] JOURNAL_TEMPLATE_VELOCITY_RESTRICTED_VARIABLES = PropsUtil.getArray(PropsKeys.JOURNAL_TEMPLATE_VELOCITY_RESTRICTED_VARIABLES);

	public static final String[] JPA_CONFIGS = PropsUtil.getArray(PropsKeys.JPA_CONFIGS);

	public static final String JPA_DATABASE_PLATFORM = PropsUtil.get(PropsKeys.JPA_DATABASE_PLATFORM);

	public static final String JPA_DATABASE_TYPE = PropsUtil.get(PropsKeys.JPA_DATABASE_TYPE);

	public static final String JPA_LOAD_TIME_WEAVER = PropsUtil.get(PropsKeys.JPA_LOAD_TIME_WEAVER);

	public static final String JPA_PROVIDER = PropsUtil.get(PropsKeys.JPA_PROVIDER);

	public static final String[] JSON_SERVICE_INVALID_CLASS_NAMES = PropsUtil.getArray(PropsKeys.JSON_SERVICE_INVALID_CLASS_NAMES);

	public static final String LAYOUT_CLONE_IMPL = PropsUtil.get(PropsKeys.LAYOUT_CLONE_IMPL);

	public static final boolean LAYOUT_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_COMMENTS_ENABLED));

	public static final boolean LAYOUT_DEFAULT_P_L_RESET = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_DEFAULT_P_L_RESET));

	public static final String LAYOUT_DEFAULT_TEMPLATE_ID = PropsUtil.get(PropsKeys.LAYOUT_DEFAULT_TEMPLATE_ID);

	public static final String LAYOUT_FRIENDLY_URL_PAGE_NOT_FOUND = PropsUtil.get(PropsKeys.LAYOUT_FRIENDLY_URL_PAGE_NOT_FOUND);

	public static final String LAYOUT_FRIENDLY_URL_PRIVATE_GROUP_SERVLET_MAPPING = PropsUtil.get(PropsKeys.LAYOUT_FRIENDLY_URL_PRIVATE_GROUP_SERVLET_MAPPING);

	public static final String LAYOUT_FRIENDLY_URL_PRIVATE_USER_SERVLET_MAPPING = PropsUtil.get(PropsKeys.LAYOUT_FRIENDLY_URL_PRIVATE_USER_SERVLET_MAPPING);

	public static final String LAYOUT_FRIENDLY_URL_PUBLIC_SERVLET_MAPPING = PropsUtil.get(PropsKeys.LAYOUT_FRIENDLY_URL_PUBLIC_SERVLET_MAPPING);

	public static final boolean LAYOUT_GUEST_SHOW_MAX_ICON = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_GUEST_SHOW_MAX_ICON));

	public static final boolean LAYOUT_GUEST_SHOW_MIN_ICON = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_GUEST_SHOW_MIN_ICON));

	public static final boolean LAYOUT_PARALLEL_RENDER_ENABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_PARALLEL_RENDER_ENABLE));

	public static final boolean LAYOUT_REMEMBER_MAXIMIZED_WINDOW_STATE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_REMEMBER_MAXIMIZED_WINDOW_STATE));

	public static final boolean LAYOUT_SHOW_HTTP_STATUS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_SHOW_HTTP_STATUS));

	public static final boolean LAYOUT_SHOW_PORTLET_ACCESS_DENIED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_SHOW_PORTLET_ACCESS_DENIED));

	public static final boolean LAYOUT_SHOW_PORTLET_INACTIVE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_SHOW_PORTLET_INACTIVE));

	public static String[] LAYOUT_STATIC_PORTLETS_ALL = PropsUtil.getArray(PropsKeys.LAYOUT_STATIC_PORTLETS_ALL);

	public static boolean LAYOUT_TEMPLATE_CACHE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_TEMPLATE_CACHE_ENABLED));

	public static String[] LAYOUT_TYPES = PropsUtil.getArray(PropsKeys.LAYOUT_TYPES);

	public static boolean LAYOUT_USER_PRIVATE_LAYOUTS_AUTO_CREATE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PRIVATE_LAYOUTS_AUTO_CREATE));

	public static boolean LAYOUT_USER_PRIVATE_LAYOUTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PRIVATE_LAYOUTS_ENABLED));

	public static boolean LAYOUT_USER_PRIVATE_LAYOUTS_MODIFIABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PRIVATE_LAYOUTS_MODIFIABLE));

	public static boolean LAYOUT_USER_PRIVATE_LAYOUTS_POWER_USER_REQUIRED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PRIVATE_LAYOUTS_POWER_USER_REQUIRED));

	public static boolean LAYOUT_USER_PUBLIC_LAYOUTS_AUTO_CREATE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PUBLIC_LAYOUTS_AUTO_CREATE));

	public static boolean LAYOUT_USER_PUBLIC_LAYOUTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PUBLIC_LAYOUTS_ENABLED));

	public static boolean LAYOUT_USER_PUBLIC_LAYOUTS_MODIFIABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PUBLIC_LAYOUTS_MODIFIABLE));

	public static boolean LAYOUT_USER_PUBLIC_LAYOUTS_POWER_USER_REQUIRED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LAYOUT_USER_PUBLIC_LAYOUTS_POWER_USER_REQUIRED));

	public static final String LDAP_ATTRS_TRANSFORMER_IMPL = PropsUtil.get(PropsKeys.LDAP_ATTRS_TRANSFORMER_IMPL);

	public static final boolean LDAP_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LDAP_AUTH_ENABLED));

	public static final boolean LDAP_EXPORT_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LDAP_EXPORT_ENABLED));

	public static final boolean LDAP_IMPORT_CREATE_ROLE_PER_GROUP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LDAP_IMPORT_CREATE_ROLE_PER_GROUP));

	public static final boolean LDAP_IMPORT_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LDAP_IMPORT_ENABLED));

	public static final long LDAP_IMPORT_INTERVAL = GetterUtil.getLong(PropsUtil.get(PropsKeys.LDAP_IMPORT_INTERVAL));

	public static final int LDAP_PAGE_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LDAP_PAGE_SIZE));

	public static final boolean LDAP_PASSWORD_POLICY_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LDAP_PASSWORD_POLICY_ENABLED));

	public static final int LDAP_RANGE_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LDAP_RANGE_SIZE));

	public static final String LDAP_USER_IMPL = PropsUtil.get(PropsKeys.LDAP_USER_IMPL);

	public static final String LIFERAY_HOME = PropsUtil.get(PropsKeys.LIFERAY_HOME);

	public static final boolean LIVE_USERS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LIVE_USERS_ENABLED));

	public static final boolean LOCALE_DEFAULT_REQUEST = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LOCALE_DEFAULT_REQUEST));

	public static final int LOCALE_PREPEND_FRIENDLY_URL_STYLE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LOCALE_PREPEND_FRIENDLY_URL_STYLE));

	public static String[] LOCALES = PropsUtil.getArray(PropsKeys.LOCALES);

	public static boolean LOGIN_CREATE_ACCOUNT_ALLOW_CUSTOM_PASSWORD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LOGIN_CREATE_ACCOUNT_ALLOW_CUSTOM_PASSWORD));

	public static final String[] LOGIN_EVENTS_POST = PropsUtil.getArray(PropsKeys.LOGIN_EVENTS_POST);

	public static final String[] LOGIN_EVENTS_PRE = PropsUtil.getArray(PropsKeys.LOGIN_EVENTS_PRE);

	public static final String[] LOGOUT_EVENTS_POST = PropsUtil.getArray(PropsKeys.LOGOUT_EVENTS_POST);

	public static final String[] LOGOUT_EVENTS_PRE = PropsUtil.getArray(PropsKeys.LOGOUT_EVENTS_PRE);

	public static final boolean LOOK_AND_FEEL_MODIFIABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LOOK_AND_FEEL_MODIFIABLE));

	public static final int LUCENE_BUFFER_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LUCENE_BUFFER_SIZE));

	public static final int LUCENE_COMMIT_BATCH_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LUCENE_COMMIT_BATCH_SIZE));

	public static final int LUCENE_COMMIT_TIME_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LUCENE_COMMIT_TIME_INTERVAL));

	public static final String LUCENE_DIR = PropsUtil.get(PropsKeys.LUCENE_DIR);

	public static final String LUCENE_FILE_EXTRACTOR = PropsUtil.get(PropsKeys.LUCENE_FILE_EXTRACTOR);

	public static final String LUCENE_FILE_EXTRACTOR_REGEXP_STRIP = PropsUtil.get(PropsKeys.LUCENE_FILE_EXTRACTOR_REGEXP_STRIP);

	public static final int LUCENE_MERGE_FACTOR = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LUCENE_MERGE_FACTOR));

	public static final int LUCENE_OPTIMIZE_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LUCENE_OPTIMIZE_INTERVAL));

	public static final boolean LUCENE_REPLICATE_WRITE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LUCENE_REPLICATE_WRITE));

	public static final boolean LUCENE_STORE_JDBC_AUTO_CLEAN_UP_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.LUCENE_STORE_JDBC_AUTO_CLEAN_UP_ENABLED));

	public static final int LUCENE_STORE_JDBC_AUTO_CLEAN_UP_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.LUCENE_STORE_JDBC_AUTO_CLEAN_UP_INTERVAL));

	public static final String LUCENE_STORE_TYPE = PropsUtil.get(PropsKeys.LUCENE_STORE_TYPE);

	public static final String MAIL_AUDIT_TRAIL = PropsUtil.get(PropsKeys.MAIL_AUDIT_TRAIL);

	public static final String MAIL_HOOK_IMPL = PropsUtil.get(PropsKeys.MAIL_HOOK_IMPL);

	public static final boolean MAIL_MX_UPDATE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MAIL_MX_UPDATE));

	public static final String MAIL_SESSION_MAIL_ADVANCED_PROPERTIES = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_ADVANCED_PROPERTIES);

	public static final String MAIL_SESSION_MAIL_POP3_HOST = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_POP3_HOST);

	public static final String MAIL_SESSION_MAIL_POP3_PASSWORD = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_POP3_PASSWORD);

	public static final int MAIL_SESSION_MAIL_POP3_PORT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_POP3_PORT));

	public static final String MAIL_SESSION_MAIL_POP3_USER = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_POP3_USER);

	public static final String MAIL_SESSION_MAIL_SMTP_HOST = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_SMTP_HOST);

	public static final String MAIL_SESSION_MAIL_SMTP_PASSWORD = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_SMTP_PASSWORD);

	public static final int MAIL_SESSION_MAIL_SMTP_PORT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_SMTP_PORT));

	public static final String MAIL_SESSION_MAIL_SMTP_USER = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_SMTP_USER);

	public static final String MAIL_SESSION_MAIL_STORE_PROTOCOL = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_STORE_PROTOCOL);

	public static final String MAIL_SESSION_MAIL_TRANSPORT_PROTOCOL = PropsUtil.get(PropsKeys.MAIL_SESSION_MAIL_TRANSPORT_PROTOCOL);

	public static final boolean MESSAGE_BOARDS_ANONYMOUS_POSTING_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_ANONYMOUS_POSTING_ENABLED));

	public static final String MESSAGE_BOARDS_EMAIL_FROM_ADDRESS = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_FROM_ADDRESS);

	public static final String MESSAGE_BOARDS_EMAIL_FROM_NAME = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_FROM_NAME);

	public static final boolean MESSAGE_BOARDS_EMAIL_HTML_FORMAT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_HTML_FORMAT));

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_BODY = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_BODY);

	public static final boolean MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_ENABLED));

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_SIGNATURE = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_SIGNATURE);

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_SUBJECT_PREFIX = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_SUBJECT_PREFIX);

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_BODY = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_BODY);

	public static final boolean MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_ENABLED));

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_SIGNATURE = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_SIGNATURE);

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_SUBJECT_PREFIX = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_SUBJECT_PREFIX);

	public static final int MESSAGE_BOARDS_EXPIRE_BAN_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EXPIRE_BAN_INTERVAL));

	public static final long MESSAGE_BOARDS_EXPIRE_BAN_JOB_INTERVAL = GetterUtil.getLong(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_EXPIRE_BAN_JOB_INTERVAL));

	public static final boolean MESSAGE_BOARDS_PINGBACK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_PINGBACK_ENABLED));

	public static final boolean MESSAGE_BOARDS_THREAD_PREVIOUS_AND_NEXT_NAVIGATION_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MESSAGE_BOARDS_THREAD_PREVIOUS_AND_NEXT_NAVIGATION_ENABLED));

	public static final String[] MESSAGE_BOARDS_THREAD_VIEWS = PropsUtil.getArray(PropsKeys.MESSAGE_BOARDS_THREAD_VIEWS);

	public static final String MESSAGE_BOARDS_THREAD_VIEWS_DEFAULT = PropsUtil.get(PropsKeys.MESSAGE_BOARDS_THREAD_VIEWS_DEFAULT);

	public static final String[] MIME_TYPES_CONTENT_DISPOSITION_INLINE = PropsUtil.getArray(PropsKeys.MIME_TYPES_CONTENT_DISPOSITION_INLINE);

	public static final int MINIFIER_INLINE_CONTENT_CACHE_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.MINIFIER_INLINE_CONTENT_CACHE_SIZE));

	public static final String[] MINIFIER_INLINE_CONTENT_CACHE_SKIP_CSS = PropsUtil.getArray(PropsKeys.MINIFIER_INLINE_CONTENT_CACHE_SKIP_CSS);

	public static final String[] MINIFIER_INLINE_CONTENT_CACHE_SKIP_JAVASCRIPT = PropsUtil.getArray(PropsKeys.MINIFIER_INLINE_CONTENT_CACHE_SKIP_JAVASCRIPT);

	public static final boolean MONITORING_DATA_SAMPLE_THREAD_LOCAL = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_DATA_SAMPLE_THREAD_LOCAL));

	public static boolean MONITORING_PORTAL_REQUEST = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_PORTAL_REQUEST));

	public static boolean MONITORING_PORTLET_ACTION_REQUEST = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_PORTLET_ACTION_REQUEST));

	public static boolean MONITORING_PORTLET_EVENT_REQUEST = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_PORTLET_EVENT_REQUEST));

	public static boolean MONITORING_PORTLET_RENDER_REQUEST = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_PORTLET_RENDER_REQUEST));

	public static boolean MONITORING_PORTLET_RESOURCE_REQUEST = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_PORTLET_RESOURCE_REQUEST));

	public static final boolean MONITORING_SHOW_PER_REQUEST_DATA_SAMPLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MONITORING_SHOW_PER_REQUEST_DATA_SAMPLE));

	public static final String MY_PLACES_DISPLAY_STYLE = PropsUtil.get(PropsKeys.MY_PLACES_DISPLAY_STYLE);

	public static final int MY_PLACES_MAX_ELEMENTS = GetterUtil.getInteger(PropsUtil.get(PropsKeys.MY_PLACES_MAX_ELEMENTS));

	public static boolean MY_PLACES_SHOW_COMMUNITY_PRIVATE_SITES_WITH_NO_LAYOUTS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MY_PLACES_SHOW_COMMUNITY_PRIVATE_SITES_WITH_NO_LAYOUTS));

	public static boolean MY_PLACES_SHOW_COMMUNITY_PUBLIC_SITES_WITH_NO_LAYOUTS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MY_PLACES_SHOW_COMMUNITY_PUBLIC_SITES_WITH_NO_LAYOUTS));

	public static boolean MY_PLACES_SHOW_ORGANIZATION_PRIVATE_SITES_WITH_NO_LAYOUTS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MY_PLACES_SHOW_ORGANIZATION_PRIVATE_SITES_WITH_NO_LAYOUTS));

	public static boolean MY_PLACES_SHOW_ORGANIZATION_PUBLIC_SITES_WITH_NO_LAYOUTS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MY_PLACES_SHOW_ORGANIZATION_PUBLIC_SITES_WITH_NO_LAYOUTS));

	public static boolean MY_PLACES_SHOW_USER_PRIVATE_SITES_WITH_NO_LAYOUTS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MY_PLACES_SHOW_USER_PRIVATE_SITES_WITH_NO_LAYOUTS));

	public static boolean MY_PLACES_SHOW_USER_PUBLIC_SITES_WITH_NO_LAYOUTS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.MY_PLACES_SHOW_USER_PUBLIC_SITES_WITH_NO_LAYOUTS));

	public static final String NESTED_PORTLETS_LAYOUT_TEMPLATE_DEFAULT = PropsUtil.get(PropsKeys.NESTED_PORTLETS_LAYOUT_TEMPLATE_DEFAULT);

	public static final String NETVIBES_SERVLET_MAPPING = PropsUtil.get(PropsKeys.NETVIBES_SERVLET_MAPPING);

	public static final boolean NTLM_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.NTLM_AUTH_ENABLED));

	public static final String NTLM_DOMAIN = PropsUtil.get(PropsKeys.NTLM_DOMAIN);

	public static final String NTLM_DOMAIN_CONTROLLER = PropsUtil.get(PropsKeys.NTLM_DOMAIN_CONTROLLER);

	public static final String NTLM_DOMAIN_CONTROLLER_NAME = PropsUtil.get(PropsKeys.NTLM_DOMAIN_CONTROLLER_NAME);

	public static final String NTLM_SERVICE_ACCOUNT = PropsUtil.get(PropsKeys.NTLM_SERVICE_ACCOUNT);

	public static final String NTLM_SERVICE_PASSWORD = PropsUtil.get(PropsKeys.NTLM_SERVICE_PASSWORD);

	public static final long[] OMNIADMIN_USERS = StringUtil.split(PropsUtil.get(PropsKeys.OMNIADMIN_USERS), 0L);

	public static final boolean OPEN_ID_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.OPEN_ID_AUTH_ENABLED));

	public static final boolean OPEN_SSO_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.OPEN_SSO_AUTH_ENABLED));

	public static final String OPEN_SSO_EMAIL_ADDRESS_ATTR = PropsUtil.get(PropsKeys.OPEN_SSO_EMAIL_ADDRESS_ATTR);

	public static final String OPEN_SSO_FIRST_NAME_ATTR = PropsUtil.get(PropsKeys.OPEN_SSO_FIRST_NAME_ATTR);

	public static final String OPEN_SSO_LAST_NAME_ATTR = PropsUtil.get(PropsKeys.OPEN_SSO_LAST_NAME_ATTR);

	public static final boolean OPEN_SSO_LDAP_IMPORT_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.OPEN_SSO_LDAP_IMPORT_ENABLED));

	public static final String OPEN_SSO_LOGIN_URL = PropsUtil.get(PropsKeys.OPEN_SSO_LOGIN_URL);

	public static final String OPEN_SSO_LOGOUT_URL = PropsUtil.get(PropsKeys.OPEN_SSO_LOGOUT_URL);

	public static final String OPEN_SSO_SCREEN_NAME_ATTR = PropsUtil.get(PropsKeys.OPEN_SSO_SCREEN_NAME_ATTR);

	public static final String OPEN_SSO_SERVICE_URL = PropsUtil.get(PropsKeys.OPEN_SSO_SERVICE_URL);

	public static final boolean OPENOFFICE_CACHE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.OPENOFFICE_CACHE_ENABLED));

	public static final boolean OPENOFFICE_SERVER_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.OPENOFFICE_SERVER_ENABLED));

	public static final String OPENOFFICE_SERVER_HOST = PropsUtil.get(PropsKeys.OPENOFFICE_SERVER_HOST);

	public static final int OPENOFFICE_SERVER_PORT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.OPENOFFICE_SERVER_PORT));

	public static final boolean ORGANIZATIONS_ASSIGNMENT_AUTO = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ORGANIZATIONS_ASSIGNMENT_AUTO));

	public static final boolean ORGANIZATIONS_ASSIGNMENT_STRICT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ORGANIZATIONS_ASSIGNMENT_STRICT));

	public static final String[] ORGANIZATIONS_FORM_ADD_IDENTIFICATION = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_FORM_ADD_IDENTIFICATION);

	public static final String[] ORGANIZATIONS_FORM_ADD_MAIN = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_FORM_ADD_MAIN);

	public static final String[] ORGANIZATIONS_FORM_ADD_MISCELLANEOUS = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_FORM_ADD_MISCELLANEOUS);

	public static final String[] ORGANIZATIONS_FORM_UPDATE_IDENTIFICATION = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_FORM_UPDATE_IDENTIFICATION);

	public static final String[] ORGANIZATIONS_FORM_UPDATE_MAIN = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_FORM_UPDATE_MAIN);

	public static final String[] ORGANIZATIONS_FORM_UPDATE_MISCELLANEOUS = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_FORM_UPDATE_MISCELLANEOUS);

	public static final boolean ORGANIZATIONS_MEMBERSHIP_STRICT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ORGANIZATIONS_MEMBERSHIP_STRICT));

	public static final boolean ORGANIZATIONS_SEARCH_WITH_INDEX = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ORGANIZATIONS_SEARCH_WITH_INDEX));

	public static String[] ORGANIZATIONS_TYPES = PropsUtil.getArray(PropsKeys.ORGANIZATIONS_TYPES);

	public static final boolean ORGANIZATIONS_USER_GROUP_MEMBERSHIP_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.ORGANIZATIONS_USER_GROUP_MEMBERSHIP_ENABLED));

	public static final String PASSWORDS_DEFAULT_POLICY_NAME = PropsUtil.get(PropsKeys.PASSWORDS_DEFAULT_POLICY_NAME);

	public static final String PASSWORDS_DIGEST_ENCODING = PropsUtil.get(PropsKeys.PASSWORDS_DIGEST_ENCODING);

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_LOWERCASE = PropsUtil.get(PropsKeys.PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_LOWERCASE);

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_NUMBERS = PropsUtil.get(PropsKeys.PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_NUMBERS);

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_SYMBOLS = PropsUtil.get(PropsKeys.PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_SYMBOLS);

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_UPPERCASE = PropsUtil.get(PropsKeys.PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_UPPERCASE);

	public static String PASSWORDS_PASSWORDPOLICYTOOLKIT_GENERATOR = PropsUtil.get(PropsKeys.PASSWORDS_PASSWORDPOLICYTOOLKIT_GENERATOR);

	public static String PASSWORDS_PASSWORDPOLICYTOOLKIT_STATIC = PropsUtil.get(PropsKeys.PASSWORDS_PASSWORDPOLICYTOOLKIT_STATIC);

	public static final String PERMISSIONS_CHECKER = PropsUtil.get(PropsKeys.PERMISSIONS_CHECKER);

	public static final String PERMISSIONS_LIST_FILTER = PropsUtil.get(PropsKeys.PERMISSIONS_LIST_FILTER);

	public static final boolean PERMISSIONS_OBJECT_BLOCKING_CACHE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PERMISSIONS_OBJECT_BLOCKING_CACHE));

	public static final int PERMISSIONS_THREAD_LOCAL_CACHE_MAX_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.PERMISSIONS_THREAD_LOCAL_CACHE_MAX_SIZE));

	public static int PERMISSIONS_USER_CHECK_ALGORITHM = GetterUtil.getInteger(PropsUtil.get(PropsKeys.PERMISSIONS_USER_CHECK_ALGORITHM));

	public static boolean PERMISSIONS_VIEW_DYNAMIC_INHERITANCE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PERMISSIONS_VIEW_DYNAMIC_INHERITANCE));

	public static final String PERSISTENCE_PROVIDER= GetterUtil.getString(PropsUtil.get(PropsKeys.PERSISTENCE_PROVIDER));

	public static final boolean PLUGIN_NOTIFICATIONS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PLUGIN_NOTIFICATIONS_ENABLED));

	public static final String[] PLUGIN_NOTIFICATIONS_PACKAGES_IGNORED = StringUtil.split(PropsUtil.get(PropsKeys.PLUGIN_NOTIFICATIONS_PACKAGES_IGNORED), StringPool.NEW_LINE);

	public static final String[] PLUGIN_REPOSITORIES_TRUSTED = StringUtil.split(PropsUtil.get(PropsKeys.PLUGIN_REPOSITORIES_TRUSTED), StringPool.NEW_LINE);

	public static final String[] PLUGIN_REPOSITORIES_UNTRUSTED = StringUtil.split(PropsUtil.get(PropsKeys.PLUGIN_REPOSITORIES_UNTRUSTED), StringPool.NEW_LINE);

	public static final String[] PLUGIN_TYPES = PropsUtil.getArray(PropsKeys.PLUGIN_TYPES);

	public static final long POLLER_REQUEST_TIMEOUT = GetterUtil.getLong(PropsUtil.get(PropsKeys.POLLER_REQUEST_TIMEOUT));

	public static final boolean POP_SERVER_NOTIFICATIONS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.POP_SERVER_NOTIFICATIONS_ENABLED));

	public static final int POP_SERVER_NOTIFICATIONS_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.POP_SERVER_NOTIFICATIONS_INTERVAL));

	public static final String POP_SERVER_SUBDOMAIN = PropsUtil.get(PropsKeys.POP_SERVER_SUBDOMAIN);

	public static final boolean PORTAL_IMPERSONATION_ENABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTAL_IMPERSONATION_ENABLE));

	public static final boolean PORTAL_JAAS_ENABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTAL_JAAS_ENABLE));

	public static final String PORTAL_JAAS_IMPL = PropsUtil.get(PropsKeys.PORTAL_JAAS_IMPL);

	public static final boolean PORTAL_JAAS_STRICT_PASSWORD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTAL_JAAS_STRICT_PASSWORD));

	public static final boolean PORTAL_SECURITY_MANAGER_ENABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTAL_SECURITY_MANAGER_ENABLE));

	public static boolean PORTLET_ADD_DEFAULT_RESOURCE_CHECK_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTLET_ADD_DEFAULT_RESOURCE_CHECK_ENABLED));

	public static final String[] PORTLET_ADD_DEFAULT_RESOURCE_CHECK_WHITELIST = PropsUtil.getArray(PropsKeys.PORTLET_ADD_DEFAULT_RESOURCE_CHECK_WHITELIST);

	public static final String[] PORTLET_ADD_DEFAULT_RESOURCE_CHECK_WHITELIST_ACTIONS = PropsUtil.getArray(PropsKeys.PORTLET_ADD_DEFAULT_RESOURCE_CHECK_WHITELIST_ACTIONS);

	public static final boolean PORTLET_CSS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTLET_CSS_ENABLED));

	public static final String PORTLET_EVENT_DISTRIBUTION = PropsUtil.get(PropsKeys.PORTLET_EVENT_DISTRIBUTION);

	public static final boolean PORTLET_EVENT_DISTRIBUTION_LAYOUT = PORTLET_EVENT_DISTRIBUTION.equalsIgnoreCase("layout");

	public static final boolean PORTLET_EVENT_DISTRIBUTION_LAYOUT_SET = !PORTLET_EVENT_DISTRIBUTION_LAYOUT;

	public static final String PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION = PropsUtil.get(PropsKeys.PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION);

	public static final boolean PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION_LAYOUT = PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION.equalsIgnoreCase("layout");

	public static final boolean PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION_LAYOUT_SET = !PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION_LAYOUT;

	public static final String PORTLET_RESOURCE_ID_BANNED_PATHS_REGEXP = PropsUtil.get(PropsKeys.PORTLET_RESOURCE_ID_BANNED_PATHS_REGEXP);

	public static final boolean PORTLET_URL_ANCHOR_ENABLE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTLET_URL_ANCHOR_ENABLE));

	public static final boolean PORTLET_URL_APPEND_PARAMETERS = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTLET_URL_APPEND_PARAMETERS));

	public static final boolean PORTLET_URL_ESCAPE_XML = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTLET_URL_ESCAPE_XML));

	public static final String PORTLET_VIRTUAL_PATH = PropsUtil.get(PropsKeys.PORTLET_VIRTUAL_PATH);

	public static final boolean PORTLET_XML_VALIDATE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PORTLET_XML_VALIDATE));

	public static final boolean PREFERENCE_VALIDATE_ON_STARTUP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.PREFERENCE_VALIDATE_ON_STARTUP));

	public static final String[] REDIRECT_URL_DOMAINS_ALLOWED = PropsUtil.getArray(PropsKeys.REDIRECT_URL_DOMAINS_ALLOWED);

	public static final String[] REDIRECT_URL_IPS_ALLOWED = PropsUtil.getArray(PropsKeys.REDIRECT_URL_IPS_ALLOWED);

	public static final String REDIRECT_URL_SECURITY_MODE = PropsUtil.get(PropsKeys.REDIRECT_URL_SECURITY_MODE);

	public static final boolean REQUEST_HEADER_AUTH_IMPORT_FROM_LDAP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.REQUEST_HEADER_AUTH_IMPORT_FROM_LDAP));

	public static final String[] REQUEST_SHARED_ATTRIBUTES = PropsUtil.getArray(PropsKeys.REQUEST_SHARED_ATTRIBUTES);

	public static String[] RESOURCE_ACTIONS_CONFIGS = PropsUtil.getArray(PropsKeys.RESOURCE_ACTIONS_CONFIGS);

	public static final boolean RESOURCE_ACTIONS_READ_PORTLET_RESOURCES = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.RESOURCE_ACTIONS_READ_PORTLET_RESOURCES));

	public static final String RESOURCE_REPOSITORIES_ROOT = PropsUtil.get(PropsKeys.RESOURCE_REPOSITORIES_ROOT);

	public static final String[] ROLES_COMMUNITY_SUBTYPES = PropsUtil.getArray(PropsKeys.ROLES_COMMUNITY_SUBTYPES);

	public static final String[] ROLES_ORGANIZATION_SUBTYPES = PropsUtil.getArray(PropsKeys.ROLES_ORGANIZATION_SUBTYPES);

	public static final String[] ROLES_REGULAR_SUBTYPES = PropsUtil.getArray(PropsKeys.ROLES_REGULAR_SUBTYPES);

	public static final String SANDBOX_DEPLOY_DIR = PropsUtil.get(PropsKeys.SANDBOX_DEPLOY_DIR);

	public static final boolean SANDBOX_DEPLOY_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SANDBOX_DEPLOY_ENABLED));

	public static final long SANDBOX_DEPLOY_INTERVAL = GetterUtil.getLong(PropsUtil.get(PropsKeys.SANDBOX_DEPLOY_INTERVAL));

	public static final String SANITIZER_IMPL = PropsUtil.get(PropsKeys.SANITIZER_IMPL);

	public static final boolean SC_PRODUCT_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SC_PRODUCT_COMMENTS_ENABLED));

	public static final String[] SCHEDULER_CLASSES = PropsUtil.getArray(PropsKeys.SCHEDULER_CLASSES);

	public static final boolean SCHEDULER_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SCHEDULER_ENABLED));

	public static final String[] SCRIPTING_FORBIDDEN_CLASSES = PropsUtil.getArray(PropsKeys.SCRIPTING_FORBIDDEN_CLASSES);

	public static final int[] SEARCH_CONTAINER_PAGE_DELTA_VALUES = GetterUtil.getIntegerValues(PropsUtil.getArray(PropsKeys.SEARCH_CONTAINER_PAGE_DELTA_VALUES));

	public static final int SEARCH_CONTAINER_PAGE_ITERATOR_MAX_PAGES = GetterUtil.getInteger(PropsUtil.get(PropsKeys.SEARCH_CONTAINER_PAGE_ITERATOR_MAX_PAGES));

	public static final boolean SEARCH_CONTAINER_SHOW_PAGINATION_BOTTOM = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SEARCH_CONTAINER_SHOW_PAGINATION_BOTTOM));

	public static final boolean SEARCH_CONTAINER_SHOW_PAGINATION_TOP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SEARCH_CONTAINER_SHOW_PAGINATION_TOP));

	public static final String[] SERVICE_BUILDER_SERVICE_READ_ONLY_PREFIXES = PropsUtil.getArray(PropsKeys.SERVICE_BUILDER_SERVICE_READ_ONLY_PREFIXES);

	public static final String[] SERVLET_SERVICE_EVENTS_POST = PropsUtil.getArray(PropsKeys.SERVLET_SERVICE_EVENTS_POST);

	public static final String[] SERVLET_SERVICE_EVENTS_PRE = PropsUtil.getArray(PropsKeys.SERVLET_SERVICE_EVENTS_PRE);

	public static final String SERVLET_SERVICE_EVENTS_PRE_ERROR_PAGE = PropsUtil.get(PropsKeys.SERVLET_SERVICE_EVENTS_PRE_ERROR_PAGE);

	public static final String[] SERVLET_SESSION_CREATE_EVENTS = PropsUtil.getArray(PropsKeys.SERVLET_SESSION_CREATE_EVENTS);

	public static final String[] SERVLET_SESSION_DESTROY_EVENTS = PropsUtil.getArray(PropsKeys.SERVLET_SESSION_DESTROY_EVENTS);

	public static final String SESSION_COOKIE_DOMAIN = PropsUtil.get(PropsKeys.SESSION_COOKIE_DOMAIN);

	public static final boolean SESSION_DISABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_DISABLED));

	public static final boolean SESSION_ENABLE_PERSISTENT_COOKIES = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_ENABLE_PERSISTENT_COOKIES));

	public static final boolean SESSION_ENABLE_PHISHING_PROTECTION = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_ENABLE_PHISHING_PROTECTION));

	public static final boolean SESSION_ENABLE_URL_WITH_SESSION_ID = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_ENABLE_URL_WITH_SESSION_ID));

	public static String[] SESSION_PHISHING_PROTECTED_ATTRIBUTES = PropsUtil.getArray(PropsKeys.SESSION_PHISHING_PROTECTED_ATTRIBUTES);

	public static final boolean SESSION_STORE_PASSWORD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_STORE_PASSWORD));

	public static final boolean SESSION_TEST_COOKIE_SUPPORT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_TEST_COOKIE_SUPPORT));

	public static int SESSION_TIMEOUT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.SESSION_TIMEOUT));

	public static final boolean SESSION_TIMEOUT_AUTO_EXTEND = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_TIMEOUT_AUTO_EXTEND));

	public static final boolean SESSION_TIMEOUT_REDIRECT_ON_EXPIRE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_TIMEOUT_REDIRECT_ON_EXPIRE));

	public static final int SESSION_TIMEOUT_WARNING = GetterUtil.getInteger(PropsUtil.get(PropsKeys.SESSION_TIMEOUT_WARNING));

	public static final boolean SESSION_TRACKER_FRIENDLY_PATHS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_TRACKER_FRIENDLY_PATHS_ENABLED));

	public static final boolean SESSION_TRACKER_MEMORY_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_TRACKER_MEMORY_ENABLED));

	public static final boolean SESSION_TRACKER_PERSISTENCE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SESSION_TRACKER_PERSISTENCE_ENABLED));

	public static final String[] SHARD_AVAILABLE_NAMES = PropsUtil.getArray(PropsKeys.SHARD_AVAILABLE_NAMES);

	public static final String SHARD_DEFAULT_NAME = PropsUtil.get(PropsKeys.SHARD_DEFAULT_NAME);

	public static final String SHARD_SELECTOR = PropsUtil.get(PropsKeys.SHARD_SELECTOR);

	public static final String[] SHARED_SESSION_ATTRIBUTES = PropsUtil.getArray(PropsKeys.SESSION_SHARED_ATTRIBUTES);

	public static final String[] SHARED_SESSION_ATTRIBUTES_EXCLUDES = PropsUtil.getArray(PropsKeys.SESSION_SHARED_ATTRIBUTES_EXCLUDES);
	
	//Chris Jurado 4 August 2011
	
	public static final boolean SHIBBOLETH_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SHIBBOLETH_AUTH_ENABLED));
	
	public static final String SHIBBOLETH_USER_HEADER = PropsUtil.get(PropsKeys.SHIBBOLETH_USER_HEADER);
	//

	public static final boolean SHOPPING_ORDER_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SHOPPING_ORDER_COMMENTS_ENABLED));

	public static final boolean SITEMINDER_AUTH_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SITEMINDER_AUTH_ENABLED));

	public static final boolean SITEMINDER_IMPORT_FROM_LDAP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SITEMINDER_IMPORT_FROM_LDAP));

	public static final String SITEMINDER_USER_HEADER = PropsUtil.get(PropsKeys.SITEMINDER_USER_HEADER);

	public static final int SOCIAL_EQUITY_EQUITY_LOG_CHECK_INTERVAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.SOCIAL_EQUITY_EQUITY_LOG_CHECK_INTERVAL));

	public static final boolean SOCIAL_EQUITY_EQUITY_LOG_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SOCIAL_EQUITY_EQUITY_LOG_ENABLED));

	public static final String[] SPRING_CONFIGS = PropsUtil.getArray(PropsKeys.SPRING_CONFIGS);

	public static boolean SPRING_HIBERNATE_SESSION_DELEGATED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.SPRING_HIBERNATE_SESSION_DELEGATED));

	public static final int SQL_DATA_MAX_PARAMETERS = GetterUtil.getInteger(PropsUtil.get(PropsKeys.SQL_DATA_MAX_PARAMETERS));

	public static final String[] STRIP_IGNORE_PATHS = PropsUtil.getArray(PropsKeys.STRIP_IGNORE_PATHS);

	public static final String STRUTS_PORTLET_REQUEST_PROCESSOR = PropsUtil.get(PropsKeys.STRUTS_PORTLET_REQUEST_PROCESSOR);

	public static final boolean TAGS_COMPILER_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.TAGS_COMPILER_ENABLED));

	public static final String TASKS_DEFAULT_ROLE_NAMES = PropsUtil.get(PropsKeys.TASKS_DEFAULT_ROLE_NAMES);

	public static final int TASKS_DEFAULT_STAGES = GetterUtil.getInteger(PropsUtil.get(PropsKeys.TASKS_DEFAULT_STAGES));

	public static final boolean TCK_URL = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.TCK_URL));

	public static final long TERMS_OF_USE_JOURNAL_ARTICLE_GROUP_ID = GetterUtil.getLong(PropsUtil.get(PropsKeys.TERMS_OF_USE_JOURNAL_ARTICLE_GROUP_ID));

	public static final String TERMS_OF_USE_JOURNAL_ARTICLE_ID = PropsUtil.get(PropsKeys.TERMS_OF_USE_JOURNAL_ARTICLE_ID);

	public static boolean TERMS_OF_USE_REQUIRED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.TERMS_OF_USE_REQUIRED));

	public static boolean THEME_CSS_FAST_LOAD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.THEME_CSS_FAST_LOAD));

	public static boolean THEME_IMAGES_FAST_LOAD = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.THEME_IMAGES_FAST_LOAD));

	public static boolean THEME_LOADER_NEW_THEME_ID_ON_IMPORT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.THEME_LOADER_NEW_THEME_ID_ON_IMPORT));

	public static final String THEME_LOADER_STORAGE_PATH = PropsUtil.get(PropsKeys.THEME_LOADER_STORAGE_PATH);

	public static boolean THEME_PORTLET_DECORATE_DEFAULT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.THEME_PORTLET_DECORATE_DEFAULT));

	public static boolean THEME_PORTLET_SHARING_DEFAULT = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.THEME_PORTLET_SHARING_DEFAULT));

	public static String THEME_SHORTCUT_ICON = PropsUtil.get(PropsKeys.THEME_SHORTCUT_ICON);

	public static final boolean THEME_SYNC_ON_GROUP = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.THEME_SYNC_ON_GROUP));

	public static final String THEME_VIRTUAL_PATH = PropsUtil.get(PropsKeys.THEME_VIRTUAL_PATH);

	public static int TRANSACTION_ISOLATION_PORTAL = GetterUtil.getInteger(PropsUtil.get(PropsKeys.TRANSACTION_ISOLATION_PORTAL));

	public static final String TRANSACTION_MANAGER_IMPL = PropsUtil.get(PropsKeys.TRANSACTION_MANAGER_IMPL);

	public static boolean TRANSACTIONAL_CACHE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.TRANSACTIONAL_CACHE_ENABLED));

	public static final boolean USERS_DELETE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_DELETE));

	public static final String USERS_EMAIL_ADDRESS_AUTO_SUFFIX = PropsUtil.get(PropsKeys.USERS_EMAIL_ADDRESS_AUTO_SUFFIX);

	public static final String USERS_EMAIL_ADDRESS_GENERATOR = PropsUtil.get(PropsKeys.USERS_EMAIL_ADDRESS_GENERATOR);

	public static boolean USERS_EMAIL_ADDRESS_REQUIRED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_EMAIL_ADDRESS_REQUIRED));

	public static final String[] USERS_EXPORT_CSV_FIELDS = PropsUtil.getArray(PropsKeys.USERS_EXPORT_CSV_FIELDS);

	public static final String[] USERS_FORM_ADD_IDENTIFICATION = PropsUtil.getArray(PropsKeys.USERS_FORM_ADD_IDENTIFICATION);

	public static final String[] USERS_FORM_ADD_MAIN = PropsUtil.getArray(PropsKeys.USERS_FORM_ADD_MAIN);

	public static final String[] USERS_FORM_ADD_MISCELLANEOUS = PropsUtil.getArray(PropsKeys.USERS_FORM_ADD_MISCELLANEOUS);

	public static final String[] USERS_FORM_MY_ACCOUNT_IDENTIFICATION = PropsUtil.getArray(PropsKeys.USERS_FORM_MY_ACCOUNT_IDENTIFICATION);

	public static final String[] USERS_FORM_MY_ACCOUNT_MAIN = PropsUtil.getArray(PropsKeys.USERS_FORM_MY_ACCOUNT_MAIN);

	public static final String[] USERS_FORM_MY_ACCOUNT_MISCELLANEOUS = PropsUtil.getArray(PropsKeys.USERS_FORM_MY_ACCOUNT_MISCELLANEOUS);

	public static final String[] USERS_FORM_UPDATE_IDENTIFICATION = PropsUtil.getArray(PropsKeys.USERS_FORM_UPDATE_IDENTIFICATION);

	public static final String[] USERS_FORM_UPDATE_MAIN = PropsUtil.getArray(PropsKeys.USERS_FORM_UPDATE_MAIN);

	public static final String[] USERS_FORM_UPDATE_MISCELLANEOUS = PropsUtil.getArray(PropsKeys.USERS_FORM_UPDATE_MISCELLANEOUS);

	public static final String USERS_FULL_NAME_GENERATOR = PropsUtil.get(PropsKeys.USERS_FULL_NAME_GENERATOR);

	public static final String USERS_FULL_NAME_VALIDATOR = PropsUtil.get(PropsKeys.USERS_FULL_NAME_VALIDATOR);

	public static final int USERS_IMAGE_MAX_HEIGHT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.USERS_IMAGE_MAX_HEIGHT));

	public static final int USERS_IMAGE_MAX_WIDTH = GetterUtil.getInteger(PropsUtil.get(PropsKeys.USERS_IMAGE_MAX_WIDTH));

	public static final boolean USERS_REMINDER_QUERIES_CUSTOM_QUESTION_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_REMINDER_QUERIES_CUSTOM_QUESTION_ENABLED));

	public static final boolean USERS_REMINDER_QUERIES_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_REMINDER_QUERIES_ENABLED));

	public static final String[] USERS_REMINDER_QUERIES_QUESTIONS = PropsUtil.getArray(PropsKeys.USERS_REMINDER_QUERIES_QUESTIONS);

	public static final boolean USERS_REMINDER_QUERIES_REQUIRED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_REMINDER_QUERIES_REQUIRED));

	public static boolean USERS_SCREEN_NAME_ALLOW_NUMERIC = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_SCREEN_NAME_ALLOW_NUMERIC));

	public static boolean USERS_SCREEN_NAME_ALWAYS_AUTOGENERATE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_SCREEN_NAME_ALWAYS_AUTOGENERATE));

	public static final String USERS_SCREEN_NAME_GENERATOR = PropsUtil.get(PropsKeys.USERS_SCREEN_NAME_GENERATOR);

	public static final String USERS_SCREEN_NAME_VALIDATOR = PropsUtil.get(PropsKeys.USERS_SCREEN_NAME_VALIDATOR);

	public static final boolean USERS_SEARCH_WITH_INDEX = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_SEARCH_WITH_INDEX));

	public static final boolean USERS_UPDATE_LAST_LOGIN = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.USERS_UPDATE_LAST_LOGIN));

	public static final boolean VALUE_OBJECT_ENTITY_BLOCKING_CACHE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.VALUE_OBJECT_ENTITY_BLOCKING_CACHE));

	public static final boolean VALUE_OBJECT_ENTITY_CACHE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.VALUE_OBJECT_ENTITY_CACHE_ENABLED));

	public static final int VALUE_OBJECT_ENTITY_THREAD_LOCAL_CACHE_MAX_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.VALUE_OBJECT_ENTITY_THREAD_LOCAL_CACHE_MAX_SIZE));

	public static final boolean VALUE_OBJECT_FINDER_BLOCKING_CACHE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.VALUE_OBJECT_FINDER_BLOCKING_CACHE));

	public static final boolean VALUE_OBJECT_FINDER_CACHE_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.VALUE_OBJECT_FINDER_CACHE_ENABLED));

	public static final int VALUE_OBJECT_FINDER_THREAD_LOCAL_CACHE_MAX_SIZE = GetterUtil.getInteger(PropsUtil.get(PropsKeys.VALUE_OBJECT_FINDER_THREAD_LOCAL_CACHE_MAX_SIZE));

	public static final String[] VELOCITY_ENGINE_RESOURCE_LISTENERS = PropsUtil.getArray(PropsKeys.VELOCITY_ENGINE_RESOURCE_LISTENERS);

	public static final String VIRTUAL_HOSTS_DEFAULT_COMMUNITY_NAME = PropsUtil.get(PropsKeys.VIRTUAL_HOSTS_DEFAULT_COMMUNITY_NAME);

	public static final String[] VIRTUAL_HOSTS_IGNORE_EXTENSIONS = PropsUtil.getArray(PropsKeys.VIRTUAL_HOSTS_IGNORE_EXTENSIONS);

	public static final boolean WEB_SERVER_DISPLAY_NODE = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.WEB_SERVER_DISPLAY_NODE));

	public static final String WEB_SERVER_HOST = PropsUtil.get(PropsKeys.WEB_SERVER_HOST);

	public static final int WEB_SERVER_HTTP_PORT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.WEB_SERVER_HTTP_PORT), -1);

	public static final int WEB_SERVER_HTTPS_PORT = GetterUtil.getInteger(PropsUtil.get(PropsKeys.WEB_SERVER_HTTPS_PORT), -1);

	public static final String WEB_SERVER_PROTOCOL = PropsUtil.get(PropsKeys.WEB_SERVER_PROTOCOL);

	public static final String[] WEBDAV_IGNORE = PropsUtil.getArray(PropsKeys.WEBDAV_IGNORE);

	public static final String WIDGET_SERVLET_MAPPING = PropsUtil.get(PropsKeys.WIDGET_SERVLET_MAPPING);

	public static final String[] WIKI_IMPORTERS = PropsUtil.getArray(PropsKeys.WIKI_IMPORTERS);

	public static final boolean WIKI_PAGE_COMMENTS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.WIKI_PAGE_COMMENTS_ENABLED));

	public static final boolean WIKI_PAGE_RATINGS_ENABLED = GetterUtil.getBoolean(PropsUtil.get(PropsKeys.WIKI_PAGE_RATINGS_ENABLED));

	public static final String WIKI_PAGE_TITLES_REGEXP = PropsUtil.get(PropsKeys.WIKI_PAGE_TITLES_REGEXP);

	public static final String WIKI_PAGE_TITLES_REMOVE_REGEXP = PropsUtil.get(PropsKeys.WIKI_PAGE_TITLES_REMOVE_REGEXP);

	static {
		if (!LAYOUT_USER_PRIVATE_LAYOUTS_ENABLED) {
			LAYOUT_USER_PRIVATE_LAYOUTS_AUTO_CREATE = false;
			LAYOUT_USER_PRIVATE_LAYOUTS_MODIFIABLE = false;
		}

		if (!LAYOUT_USER_PUBLIC_LAYOUTS_ENABLED) {
			LAYOUT_USER_PUBLIC_LAYOUTS_AUTO_CREATE = false;
			LAYOUT_USER_PUBLIC_LAYOUTS_MODIFIABLE = false;
		}
	}

}