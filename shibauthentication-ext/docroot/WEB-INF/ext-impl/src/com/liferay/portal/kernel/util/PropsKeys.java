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

package com.liferay.portal.kernel.util;

/**
 * @author Brian Wing Shun Chan
 */
public interface PropsKeys {

	public static final String ADMIN_DEFAULT_GROUP_NAMES = "admin.default.group.names";

	public static final String ADMIN_DEFAULT_ROLE_NAMES = "admin.default.role.names";

	public static final String ADMIN_DEFAULT_USER_GROUP_NAMES = "admin.default.user.group.names";

	public static final String ADMIN_EMAIL_FROM_ADDRESS = "admin.email.from.address";

	public static final String ADMIN_EMAIL_FROM_NAME = "admin.email.from.name";

	public static final String ADMIN_EMAIL_PASSWORD_RESET_BODY = "admin.email.password.reset.body";

	public static final String ADMIN_EMAIL_PASSWORD_RESET_SUBJECT = "admin.email.password.reset.subject";

	public static final String ADMIN_EMAIL_PASSWORD_SENT_BODY = "admin.email.password.sent.body";

	public static final String ADMIN_EMAIL_PASSWORD_SENT_SUBJECT = "admin.email.password.sent.subject";

	public static final String ADMIN_EMAIL_USER_ADDED_BODY = "admin.email.user.added.body";

	public static final String ADMIN_EMAIL_USER_ADDED_ENABLED = "admin.email.user.added.enabled";

	public static final String ADMIN_EMAIL_USER_ADDED_SUBJECT = "admin.email.user.added.subject";

	public static final String ADMIN_MAIL_HOST_NAMES = "admin.mail.host.names";

	public static final String ADMIN_RESERVED_EMAIL_ADDRESSES = "admin.reserved.email.addresses";

	public static final String ADMIN_RESERVED_SCREEN_NAMES = "admin.reserved.screen.names";

	public static final String ADMIN_SYNC_DEFAULT_ASSOCIATIONS = "admin.sync.default.associations";

	public static final String AIM_LOGIN = "aim.login";

	public static final String AIM_PASSWORD = "aim.password";

	public static final String AMAZON_ACCESS_KEY_ID = "amazon.access.key.id";

	public static final String AMAZON_ASSOCIATE_TAG = "amazon.associate.tag";

	public static final String ANNOUNCEMENTS_EMAIL_BODY = "announcements.email.body";

	public static final String ANNOUNCEMENTS_EMAIL_FROM_ADDRESS = "announcements.email.from.address";

	public static final String ANNOUNCEMENTS_EMAIL_FROM_NAME = "announcements.email.from.name";

	public static final String ANNOUNCEMENTS_EMAIL_SUBJECT = "announcements.email.subject";

	public static final String ANNOUNCEMENTS_EMAIL_TO_ADDRESS = "announcements.email.to.address";

	public static final String ANNOUNCEMENTS_EMAIL_TO_NAME = "announcements.email.to.name";

	public static final String ANNOUNCEMENTS_ENTRY_CHECK_INTERVAL = "announcements.entry.check.interval";

	public static final String ANNOUNCEMENTS_ENTRY_TYPES = "announcements.entry.types";

	public static final String APPLICATION_SHUTDOWN_EVENTS = "application.shutdown.events";

	public static final String APPLICATION_STARTUP_EVENTS = "application.startup.events";

	public static final String ASSET_CATEGORIES_PROPERTIES_DEFAULT = "asset.categories.properties.default";

	public static final String ASSET_CATEGORIES_SEARCH_HIERARCHICAL = "asset.categories.search.hierarchical";

	public static final String ASSET_ENTRY_INCREMENT_VIEW_COUNTER_ENABLED = "asset.entry.increment.view.counter.enabled";

	public static final String ASSET_ENTRY_VALIDATOR = "asset.entry.validator";

	public static final String ASSET_FILTER_SEARCH_LIMIT = "asset.filter.search.limit";

	public static final String ASSET_PUBLISHER_DISPLAY_STYLES = "asset.publisher.display.styles";

	public static final String ASSET_RENDERER_ENABLED = "asset.renderer.enabled.";

	public static final String ASSET_TAG_PROPERTIES_DEFAULT = "asset.tag.properties.default";

	public static final String ASSET_VOCABULARY_DEFAULT = "asset.vocabulary.default";

	public static final String AUTH_FAILURE = "auth.failure";

	public static final String AUTH_FORWARD_BY_LAST_PATH = "auth.forward.by.last.path";

	public static final String AUTH_FORWARD_BY_REDIRECT = "auth.forward.by.redirect";

	public static final String AUTH_FORWARD_LAST_PATHS = "auth.forward.last.paths";

	public static final String AUTH_LOGIN_COMMUNITY_URL = "auth.login.community.url";

	public static final String AUTH_LOGIN_PORTLET_NAME = "auth.login.portlet.name";

	public static final String AUTH_LOGIN_URL = "auth.login.url";

	public static final String AUTH_MAC_ALGORITHM = "auth.mac.algorithm";

	public static final String AUTH_MAC_ALLOW = "auth.mac.allow";

	public static final String AUTH_MAC_SHARED_KEY = "auth.mac.shared.key";

	public static final String AUTH_MAX_FAILURES = "auth.max.failures";

	public static final String AUTH_PIPELINE_ENABLE_LIFERAY_CHECK = "auth.pipeline.enable.liferay.check";

	public static final String AUTH_PIPELINE_POST = "auth.pipeline.post";

	public static final String AUTH_PIPELINE_PRE = "auth.pipeline.pre";

	public static final String AUTH_PUBLIC_PATHS = "auth.public.paths";

	public static final String AUTH_TOKEN_CHECK_ENABLED = "auth.token.check.enabled";

	public static final String AUTH_TOKEN_IGNORE_ACTIONS = "auth.token.ignore.actions";

	public static final String AUTH_TOKEN_IMPL = "auth.token.impl";

	public static final String AUTH_TOKEN_SHARED_SECRET = "auth.token.shared.secret";

	public static final String AUTO_DEPLOY_BLACKLIST_THRESHOLD = "auto.deploy.blacklist.threshold";

	public static final String AUTO_DEPLOY_CUSTOM_PORTLET_XML = "auto.deploy.custom.portlet.xml";

	public static final String AUTO_DEPLOY_DEFAULT_DEST_DIR = "auto.deploy.default.dest.dir";

	public static final String AUTO_DEPLOY_DEPLOY_DIR = "auto.deploy.deploy.dir";

	public static final String AUTO_DEPLOY_DEST_DIR = "auto.deploy.dest.dir";

	public static final String AUTO_DEPLOY_ENABLED = "auto.deploy.enabled";

	public static final String AUTO_DEPLOY_INTERVAL = "auto.deploy.interval";

	public static final String AUTO_DEPLOY_JBOSS_PREFIX = "auto.deploy.jboss.prefix";

	public static final String AUTO_DEPLOY_LISTENERS = "auto.deploy.listeners";

	public static final String AUTO_DEPLOY_TOMCAT_CONF_DIR = "auto.deploy.tomcat.conf.dir";

	public static final String AUTO_DEPLOY_TOMCAT_DEST_DIR = "auto.deploy.tomcat.dest.dir";

	public static final String AUTO_DEPLOY_TOMCAT_LIB_DIR = "auto.deploy.tomcat.lib.dir";

	public static final String AUTO_DEPLOY_UNPACK_WAR = "auto.deploy.unpack.war";

	public static final String AUTO_LOGIN_HOOKS = "auto.login.hooks";

	public static final String AUTO_LOGIN_IGNORE_HOSTS = "auto.login.ignore.hosts";

	public static final String AUTO_LOGIN_IGNORE_PATHS = "auto.login.ignore.paths";

	public static final String BASIC_AUTH_PASSWORD_REQUIRED = "basic.auth.password.required";

	public static final String BLOGS_EMAIL_COMMENTS_ADDED_BODY = "blogs.email.comments.added.body";

	public static final String BLOGS_EMAIL_COMMENTS_ADDED_ENABLED = "blogs.email.comments.added.enabled";

	public static final String BLOGS_EMAIL_COMMENTS_ADDED_SUBJECT = "blogs.email.comments.added.subject";

	public static final String BLOGS_EMAIL_ENTRY_ADDED_BODY = "blogs.email.entry.added.body";

	public static final String BLOGS_EMAIL_ENTRY_ADDED_ENABLED = "blogs.email.entry.added.enabled";

	public static final String BLOGS_EMAIL_ENTRY_ADDED_SUBJECT = "blogs.email.entry.added.subject";

	public static final String BLOGS_EMAIL_ENTRY_UPDATED_BODY = "blogs.email.entry.updated.body";

	public static final String BLOGS_EMAIL_ENTRY_UPDATED_ENABLED = "blogs.email.entry.updated.enabled";

	public static final String BLOGS_EMAIL_ENTRY_UPDATED_SUBJECT = "blogs.email.entry.updated.subject";

	public static final String BLOGS_EMAIL_FROM_ADDRESS = "blogs.email.from.address";

	public static final String BLOGS_EMAIL_FROM_NAME = "blogs.email.from.name";

	public static final String BLOGS_ENTRY_COMMENTS_ENABLED = "blogs.entry.comments.enabled";

	public static final String BLOGS_ENTRY_PREVIOUS_AND_NEXT_NAVIGATION_ENABLED = "blogs.entry.previous.and.next.navigation.enabled";

	public static final String BLOGS_LINKBACK_EXCERPT_LENGTH = "blogs.linkback.excerpt.length";

	public static final String BLOGS_LINKBACK_JOB_INTERVAL = "blogs.linkback.job.interval";

	public static final String BLOGS_PAGE_ABSTRACT_LENGTH = "blogs.page.abstract.length";

	public static final String BLOGS_PING_GOOGLE_ENABLED = "blogs.ping.google.enabled";

	public static final String BLOGS_PINGBACK_ENABLED = "blogs.pingback.enabled";

	public static final String BLOGS_RSS_ABSTRACT_LENGTH = "blogs.rss.abstract.length";

	public static final String BLOGS_TRACKBACK_ENABLED = "blogs.trackback.enabled";

	public static final String BREADCRUMB_SHOW_GUEST_GROUP = "breadcrumb.show.guest.group";

	public static final String BREADCRUMB_SHOW_PARENT_GROUPS = "breadcrumb.show.parent.groups";

	public static final String BROWSER_LAUNCHER_URL = "browser.launcher.url";

	public static final String CALENDAR_EMAIL_EVENT_REMINDER_BODY = "calendar.email.event.reminder.body";

	public static final String CALENDAR_EMAIL_EVENT_REMINDER_ENABLED = "calendar.email.event.reminder.enabled";

	public static final String CALENDAR_EMAIL_EVENT_REMINDER_SUBJECT = "calendar.email.event.reminder.subject";

	public static final String CALENDAR_EMAIL_FROM_ADDRESS = "calendar.email.from.address";

	public static final String CALENDAR_EMAIL_FROM_NAME = "calendar.email.from.name";

	public static final String CALENDAR_EVENT_CHECK_INTERVAL = "calendar.event.check.interval";

	public static final String CALENDAR_EVENT_COMMENTS_ENABLED = "calendar.event.comments.enabled";

	public static final String CALENDAR_EVENT_TYPES = "calendar.event.types";

	public static final String CAPTCHA_CHECK_PORTAL_CREATE_ACCOUNT = "captcha.check.portal.create_account";

	public static final String CAPTCHA_CHECK_PORTAL_SEND_PASSWORD = "captcha.check.portal.send_password";

	public static final String CAPTCHA_CHECK_PORTLET_MESSAGE_BOARDS_EDIT_CATEGORY = "captcha.check.portlet.message_boards.edit_category";

	public static final String CAPTCHA_CHECK_PORTLET_MESSAGE_BOARDS_EDIT_MESSAGE = "captcha.check.portlet.message_boards.edit_message";

	public static final String CAPTCHA_ENGINE_IMPL = "captcha.engine.impl";

	public static final String CAPTCHA_ENGINE_RECAPTCHA_KEY_PRIVATE = "captcha.engine.recaptcha.key.private";

	public static final String CAPTCHA_ENGINE_RECAPTCHA_KEY_PUBLIC = "captcha.engine.recaptcha.key.public";

	public static final String CAPTCHA_ENGINE_RECAPTCHA_URL_NOSCRIPT = "captcha.engine.recaptcha.url.noscript";

	public static final String CAPTCHA_ENGINE_RECAPTCHA_URL_SCRIPT = "captcha.engine.recaptcha.url.script";

	public static final String CAPTCHA_ENGINE_RECAPTCHA_URL_VERIFY = "captcha.engine.recaptcha.url.verify";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_BACKGROUND_PRODUCERS = "captcha.engine.simplecaptcha.background.producers";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_GIMPY_RENDERERS = "captcha.engine.simplecaptcha.gimpy.renderers";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_HEIGHT = "captcha.engine.simplecaptcha.height";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_NOISE_PRODUCERS = "captcha.engine.simplecaptcha.noise.producers";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_TEXT_PRODUCERS = "captcha.engine.simplecaptcha.text.producers";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_WIDTH = "captcha.engine.simplecaptcha.width";

	public static final String CAPTCHA_ENGINE_SIMPLECAPTCHA_WORD_RENDERERS = "captcha.engine.simplecaptcha.word.renderers";

	public static final String CAPTCHA_MAX_CHALLENGES = "captcha.max.challenges";

	public static final String CAS_AUTH_ENABLED = "cas.auth.enabled";

	public static final String CAS_IMPORT_FROM_LDAP = "cas.import.from.ldap";

	public static final String CAS_LOGIN_URL = "cas.login.url";

	public static final String CAS_LOGOUT_URL = "cas.logout.url";

	public static final String CAS_SERVER_NAME = "cas.server.name";

	public static final String CAS_SERVER_URL = "cas.server.url";

	public static final String CAS_SERVICE_URL = "cas.service.url";

	public static final String CDN_HOST_HTTP = "cdn.host.http";

	public static final String CDN_HOST_HTTPS = "cdn.host.https";

	public static final String CLUSTER_EXECUTOR_DEBUG_ENABLED = "cluster.executor.debug.enabled";

	public static final String CLUSTER_LINK_AUTODETECT_ADDRESS = "cluster.link.autodetect.address";

	public static final String CLUSTER_LINK_CHANNEL_PROPERTIES_CONTROL = "cluster.link.channel.properties.control";

	public static final String CLUSTER_LINK_CHANNEL_PROPERTIES_TRANSPORT = "cluster.link.channel.properties.transport";

	public static final String CLUSTER_LINK_CHANNEL_SYSTEM_PROPERTIES = "cluster.link.channel.system.properties";

	public static final String CLUSTER_LINK_ENABLED = "cluster.link.enabled";

	public static final String CMIS_CREDENTIALS_PASSWORD = "cmis.credentials.password";

	public static final String CMIS_CREDENTIALS_USERNAME = "cmis.credentials.username";

	public static final String CMIS_REPOSITORY_URL = "cmis.repository.url";

	public static final String CMIS_REPOSITORY_VERSION = "cmis.repository.version";

	public static final String CMIS_SYSTEM_ROOT_DIR = "cmis.system.root.dir";

	public static final String COMBO_CHECK_TIMESTAMP = "combo.check.timestamp";

	public static final String COMMUNITIES_CONTROL_PANEL_MEMBERS_VISIBLE = "communities.control.panel.members.visible";

	public static final String COMMUNITIES_EMAIL_FROM_ADDRESS = "communities.email.from.address";

	public static final String COMMUNITIES_EMAIL_FROM_NAME = "communities.email.from.name";

	public static final String COMMUNITIES_EMAIL_MEMBERSHIP_REPLY_BODY = "communities.email.membership.reply.body";

	public static final String COMMUNITIES_EMAIL_MEMBERSHIP_REPLY_SUBJECT = "communities.email.membership.reply.subject";

	public static final String COMMUNITIES_EMAIL_MEMBERSHIP_REQUEST_BODY = "communities.email.membership.request.body";

	public static final String COMMUNITIES_EMAIL_MEMBERSHIP_REQUEST_SUBJECT = "communities.email.membership.request.subject";

	public static final String COMPANY_DEFAULT_HOME_URL = "company.default.home.url";

	public static final String COMPANY_DEFAULT_WEB_ID = "company.default.web.id";

	public static final String COMPANY_LOGIN_PREPOPULATE_DOMAIN = "company.login.prepopulate.domain";

	public static final String COMPANY_SECURITY_AUTH_REQUIRES_HTTPS = "company.security.auth.requires.https";

	public static final String COMPANY_SECURITY_AUTH_TYPE = "company.security.auth.type";

	public static final String COMPANY_SECURITY_AUTO_LOGIN = "company.security.auto.login";

	public static final String COMPANY_SECURITY_AUTO_LOGIN_MAX_AGE = "company.security.auto.login.max.age";

	public static final String COMPANY_SECURITY_COMMUNITY_LOGO = "company.security.community.logo";

	public static final String COMPANY_SECURITY_SEND_PASSWORD = "company.security.send.password";

	public static final String COMPANY_SECURITY_SEND_PASSWORD_RESET_LINK = "company.security.send.password.reset.link";

	public static final String COMPANY_SECURITY_STRANGERS = "company.security.strangers";

	public static final String COMPANY_SECURITY_STRANGERS_URL = "company.security.strangers.url";

	public static final String COMPANY_SECURITY_STRANGERS_VERIFY = "company.security.strangers.verify";

	public static final String COMPANY_SECURITY_STRANGERS_WITH_MX = "company.security.strangers.with.mx";

	public static final String COMPANY_SETTINGS_FORM_CONFIGURATION = "company.settings.form.configuration";

	public static final String COMPANY_SETTINGS_FORM_IDENTIFICATION = "company.settings.form.identification";

	public static final String COMPANY_SETTINGS_FORM_MISCELLANEOUS = "company.settings.form.miscellaneous";

	public static final String CONTROL_PANEL_DEFAULT_ENTRY_CLASS = "control.panel.default.entry.class";

	public static final String CONTROL_PANEL_LAYOUT_FRIENDLY_URL = "control.panel.layout.friendly.url";

	public static final String CONTROL_PANEL_LAYOUT_NAME = "control.panel.layout.name";

	public static final String CONTROL_PANEL_LAYOUT_REGULAR_THEME_ID = "control.panel.layout.regular.theme.id";

	public static final String CONTROL_PANEL_NAVIGATION_MAX_COMMUNITIES = "control.panel.navigation.max.communities";

	public static final String CONTROL_PANEL_NAVIGATION_MAX_ORGANIZATIONS = "control.panel.navigation.max.organizations";

	public static final String CONVERT_PROCESSES = "convert.processes";

	public static final String COUNTER_INCREMENT = "counter.increment";

	public static final String COUNTER_INCREMENT_PREFIX = "counter.increment.";

	public static final String CUSTOM_SQL_FUNCTION_ISNOTNULL = "custom.sql.function.isnotnull";

	public static final String CUSTOM_SQL_FUNCTION_ISNULL = "custom.sql.function.isnull";

	public static final String DATABASE_MYSQL_ENGINE = "database.mysql.engine";

	public static final String DEFAULT_ADMIN_EMAIL_ADDRESS_PREFIX = "default.admin.email.address.prefix";

	public static final String DEFAULT_ADMIN_FIRST_NAME = "default.admin.first.name";

	public static final String DEFAULT_ADMIN_LAST_NAME = "default.admin.last.name";

	public static final String DEFAULT_ADMIN_MIDDLE_NAME = "default.admin.middle.name";

	public static final String DEFAULT_ADMIN_PASSWORD = "default.admin.password";

	public static final String DEFAULT_ADMIN_SCREEN_NAME = "default.admin.screen.name";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_COLUMN = "default.guest.public.layout.column-";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_FRIENDLY_URL = "default.guest.public.layout.friendly.url";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_NAME = "default.guest.public.layout.name";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_REGULAR_COLOR_SCHEME_ID = "default.guest.public.layout.regular.color.scheme.id";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_REGULAR_THEME_ID = "default.guest.public.layout.regular.theme.id";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_TEMPLATE_ID = "default.guest.public.layout.template.id";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_WAP_COLOR_SCHEME_ID = "default.guest.public.layout.wap.color.scheme.id";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUT_WAP_THEME_ID = "default.guest.public.layout.wap.theme.id";

	public static final String DEFAULT_GUEST_PUBLIC_LAYOUTS_LAR = "default.guest.public.layouts.lar";

	public static final String DEFAULT_LANDING_PAGE_PATH = "default.landing.page.path";

	public static final String DEFAULT_LAYOUT_TEMPLATE_ID = "default.layout.template.id";

	public static final String DEFAULT_LIFERAY_HOME = "default.liferay.home";

	public static final String DEFAULT_LOGOUT_PAGE_PATH = "default.logout.page.path";

	public static final String DEFAULT_REGULAR_COLOR_SCHEME_ID = "default.regular.color.scheme.id";

	public static final String DEFAULT_REGULAR_THEME_ID = "default.regular.theme.id";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_COLUMN = "default.user.private.layout.column-";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_FRIENDLY_URL = "default.user.private.layout.friendly.url";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_NAME = "default.user.private.layout.name";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_REGULAR_COLOR_SCHEME_ID = "default.user.private.layout.regular.color.scheme.id";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_REGULAR_THEME_ID = "default.user.private.layout.regular.theme.id";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_TEMPLATE_ID = "default.user.private.layout.template.id";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_WAP_COLOR_SCHEME_ID = "default.user.private.layout.wap.color.scheme.id";

	public static final String DEFAULT_USER_PRIVATE_LAYOUT_WAP_THEME_ID = "default.user.private.layout.wap.theme.id";

	public static final String DEFAULT_USER_PRIVATE_LAYOUTS_LAR = "default.user.private.layouts.lar";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_COLUMN = "default.user.public.layout.column-";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_FRIENDLY_URL = "default.user.public.layout.friendly.url";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_NAME = "default.user.public.layout.name";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_REGULAR_COLOR_SCHEME_ID = "default.user.public.layout.regular.color.scheme.id";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_REGULAR_THEME_ID = "default.user.public.layout.regular.theme.id";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_TEMPLATE_ID = "default.user.public.layout.template.id";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_WAP_COLOR_SCHEME_ID = "default.user.public.layout.wap.color.scheme.id";

	public static final String DEFAULT_USER_PUBLIC_LAYOUT_WAP_THEME_ID = "default.user.public.layout.wap.theme.id";

	public static final String DEFAULT_USER_PUBLIC_LAYOUTS_LAR = "default.user.public.layouts.lar";

	public static final String DEFAULT_WAP_COLOR_SCHEME_ID = "default.wap.color.scheme.id";

	public static final String DEFAULT_WAP_THEME_ID = "default.wap.theme.id";

	public static final String DISCUSSION_THREAD_VIEW = "discussion.thread.view";

	public static final String DL_COMPARABLE_FILE_EXTENSIONS = "dl.comparable.file.extensions";

	public static final String DL_FILE_ENTRY_COMMENTS_ENABLED = "dl.file.entry.comments.enabled";

	public static final String DL_FILE_ENTRY_READ_COUNT_ENABLED = "dl.file.entry.read.count.enabled";

	public static final String DL_FILE_EXTENSIONS = "dl.file.extensions";

	public static final String DL_FILE_EXTENSIONS_STRICT_CHECK = "dl.file.extensions.strict.check";

	public static final String DL_FILE_ICONS = "dl.file.icons";

	public static final String DL_FILE_INDEXING_MAX_SIZE = "dl.file.indexing.max.size";

	public static final String DL_FILE_MAX_SIZE = "dl.file.max.size";

	public static final String DL_FILE_RANK_ENABLED = "dl.file.rank.enabled";

	public static final String DL_HOOK_FILE_SYSTEM_ROOT_DIR = "dl.hook.file.system.root.dir";

	public static final String DL_HOOK_IMPL = "dl.hook.impl";

	public static final String DL_HOOK_JCR_FETCH_DELAY = "dl.hook.jcr.fetch.delay";

	public static final String DL_HOOK_JCR_FETCH_MAX_FAILURES = "dl.hook.jcr.fetch.max.failures";

	public static final String DL_HOOK_JCR_MOVE_VERSION_LABELS = "dl.hook.jcr.move.version.labels";

	public static final String DL_HOOK_S3_ACCESS_KEY = "dl.hook.s3.access.key";

	public static final String DL_HOOK_S3_BUCKET_NAME = "dl.hook.s3.bucket.name";

	public static final String DL_HOOK_S3_SECRET_KEY = "dl.hook.s3.secret.key";

	public static final String DL_LAYOUTS_SYNC_ENABLED = "dl.layouts.sync.enabled";

	public static final String DL_LAYOUTS_SYNC_PRIVATE_FOLDER = "dl.layouts.sync.private.folder";

	public static final String DL_LAYOUTS_SYNC_PUBLIC_FOLDER = "dl.layouts.sync.public.folder";

	public static final String DL_PUBLISH_TO_LIVE_BY_DEFAULT = "dl.publish.to.live.by.default";

	public static final String DL_WEBDAV_HOLD_LOCK = "dl.webdav.hold.lock";

	public static final String DL_WEBDAV_SAVE_TO_SINGLE_VERSION = "dl.webdav.save.to.single.version";

	public static final String DOCKBAR_ADD_PORTLETS = "dockbar.add.portlets";

	public static final String EDITOR_WYSIWYG_DEFAULT = "editor.wysiwyg.default";

	public static final String EHCACHE_BLOCKING_CACHE_ALLOWED = "ehcache.blocking.cache.allowed";

	public static final String EHCACHE_BOOTSTRAP_CACHE_LOADER_FACTORY = "ehcache.bootstrap.cache.loader.factory";

	public static final String EHCACHE_CACHE_EVENT_LISTENER_FACTORY = "ehcache.cache.event.listener.factory";

	public static final String EHCACHE_CACHE_MANAGER_PEER_PROVIDER_FACTORY = "ehcache.cache.manager.peer.provider.factory";

	public static final String EHCACHE_MULTI_VM_CONFIG_LOCATION = "ehcache.multi.vm.config.location";

	public static final String EHCACHE_PORTAL_CACHE_MANAGER_JMX_ENABLED = "ehcache.portal.cache.manager.jmx.enabled";

	public static final String EHCACHE_SINGLE_VM_CONFIG_LOCATION = "ehcache.single.vm.config.location";

	public static final String EHCACHE_STATISTICS_ENABLED = "ehcache.statistics.enabled";

	public static final String FACEBOOK_CONNECT_APP_ID = "facebook.connect.app.id";

	public static final String FACEBOOK_CONNECT_APP_SECRET = "facebook.connect.app.secret";

	public static final String FACEBOOK_CONNECT_AUTH_ENABLED = "facebook.connect.auth.enabled";

	public static final String FACEBOOK_CONNECT_GRAPH_URL = "facebook.connect.graph.url";

	public static final String FACEBOOK_CONNECT_OAUTH_AUTH_URL = "facebook.connect.oauth.auth.url";

	public static final String FACEBOOK_CONNECT_OAUTH_REDIRECT_URL = "facebook.connect.oauth.redirect.url";

	public static final String FACEBOOK_CONNECT_OAUTH_TOKEN_URL = "facebook.connect.oauth.token.url";

	public static final String FIELD_EDITABLE_COM_LIFERAY_PORTAL_MODEL_USER_EMAILADDRESS = "field.editable.com.liferay.portal.model.User.emailAddress";

	public static final String FIELD_EDITABLE_COM_LIFERAY_PORTAL_MODEL_USER_SCREENNAME = "field.editable.com.liferay.portal.model.User.screenName";

	public static final String FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_CONTACT_BIRTHDAY = "field.enable.com.liferay.portal.model.Contact.birthday";

	public static final String FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_CONTACT_MALE = "field.enable.com.liferay.portal.model.Contact.male";

	public static final String FIELD_ENABLE_COM_LIFERAY_PORTAL_MODEL_ORGANIZATION_STATUS = "field.enable.com.liferay.portal.model.Organization.status";

	public static final String FINALIZE_MANAGER_THREAD_ENABLED = "finalize.manager.thread.enabled";

	public static final String FLAGS_EMAIL_BODY = "flags.email.body";

	public static final String FLAGS_EMAIL_FROM_ADDRESS = "flags.email.from.address";

	public static final String FLAGS_EMAIL_FROM_NAME = "flags.email.from.name";

	public static final String FLAGS_EMAIL_SUBJECT = "flags.email.subject";

	public static final String FLAGS_GUEST_USERS_ENABLED = "flags.guest.users.enabled";

	public static final String FLAGS_REASONS = "flags.reasons";

	public static final String FREEMARKER_ENGINE_CACHE_ENABLED = "freemarker.engine.cache.enabled";

	public static final String FREEMARKER_ENGINE_CACHE_STORAGE = "freemarker.engine.cache.storage";

	public static final String FREEMARKER_ENGINE_LOCALIZED_LOOKUP = "freemarker.engine.localized.lookup";

	public static final String FREEMARKER_ENGINE_MACRO_LIBRARY = "freemarker.engine.macro.library";

	public static final String FREEMARKER_ENGINE_MODIFICATION_CHECK_INTERVAL = "freemarker.engine.modification.check.interval";

	public static final String FREEMARKER_ENGINE_TEMPLATE_EXCEPTION_HANDLER = "freemarker.engine.template.exception.handler";

	public static final String FREEMARKER_ENGINE_TEMPLATE_LOADERS = "freemarker.engine.template.loaders";

	public static final String GLOBAL_SHUTDOWN_EVENTS = "global.shutdown.events";

	public static final String GLOBAL_STARTUP_EVENTS = "global.startup.events";

	public static final String GOOGLE_APPS_PASSWORD = "google.apps.password";

	public static final String GOOGLE_APPS_USERNAME = "google.apps.username";

	public static final String GOOGLE_GADGET_SERVLET_MAPPING = "google.gadget.servlet.mapping";

	public static final String HIBERNATE_CONFIGS = "hibernate.configs";

	public static final String HIBERNATE_DIALECT = "hibernate.dialect";

	public static final String HIBERNATE_GENERATE_STATISTICS = "hibernate.generate_statistics";

	public static final String HIBERNATE_JDBC_BATCH_SIZE = "hibernate.jdbc.batch_size";

	public static final String HOT_DEPLOY_LISTENERS = "hot.deploy.listeners";

	public static final String HOT_UNDEPLOY_ENABLED = "hot.undeploy.enabled";

	public static final String HOT_UNDEPLOY_INTERVAL = "hot.undeploy.interval";

	public static final String HOT_UNDEPLOY_ON_REDEPLOY = "hot.undeploy.on.redeploy";

	public static final String ICQ_JAR = "icq.jar";

	public static final String ICQ_LOGIN = "icq.login";

	public static final String ICQ_PASSWORD = "icq.password";

	public static final String IFRAME_PASSWORD_PASSWORD_TOKEN_ROLE = "iframe.password.token.role";

	public static final String IG_IMAGE_CUSTOM_1_MAX_DIMENSION = "ig.image.custom1.max.dimension";

	public static final String IG_IMAGE_CUSTOM_2_MAX_DIMENSION = "ig.image.custom2.max.dimension";

	public static final String IG_IMAGE_EXTENSIONS = "ig.image.extensions";

	public static final String IG_IMAGE_MAX_SIZE = "ig.image.max.size";

	public static final String IG_IMAGE_THUMBNAIL_MAX_DIMENSION = "ig.image.thumbnail.max.dimension";

	public static final String IG_PUBLISH_TO_LIVE_BY_DEFAULT = "ig.publish.to.live.by.default";

	public static final String IMAGE_DEFAULT_COMPANY_LOGO = "image.default.company.logo";

	public static final String IMAGE_DEFAULT_ORGANIZATION_LOGO = "image.default.organization.logo";

	public static final String IMAGE_DEFAULT_SPACER = "image.default.spacer";

	public static final String IMAGE_DEFAULT_USER_FEMALE_PORTRAIT = "image.default.user.female.portrait";

	public static final String IMAGE_DEFAULT_USER_MALE_PORTRAIT = "image.default.user.male.portrait";

	public static final String IMAGE_HOOK_FILE_SYSTEM_ROOT_DIR = "image.hook.file.system.root.dir";

	public static final String IMAGE_HOOK_IMPL = "image.hook.impl";

	public static final String INDEX_FILTER_SEARCH_LIMIT = "index.filter.search.limit";

	public static final String INDEX_ON_STARTUP = "index.on.startup";

	public static final String INDEX_ON_STARTUP_DELAY = "index.on.startup.delay";

	public static final String INDEX_ON_UPGRADE = "index.on.upgrade";

	public static final String INDEX_READ_ONLY = "index.read.only";

	public static final String INDEX_WITH_THREAD = "index.with.thread";

	public static final String INVITATION_EMAIL_MAX_RECIPIENTS = "invitation.email.max.recipients";

	public static final String INVITATION_EMAIL_MESSAGE_BODY = "invitation.email.message.body";

	public static final String INVITATION_EMAIL_MESSAGE_SUBJECT = "invitation.email.message.subject";

	public static final String JAVASCRIPT_BAREBONE_ENABLED = "javascript.barebone.enabled";

	public static final String JAVASCRIPT_BAREBONE_FILES = "javascript.barebone.files";

	public static final String JAVASCRIPT_BUNDLE_DEPENDENCIES = "javascript.bundle.dependencies";

	public static final String JAVASCRIPT_BUNDLE_DIR = "javascript.bundle.dir";

	public static final String JAVASCRIPT_BUNDLE_IDS = "javascript.bundle.ids";

	public static final String JAVASCRIPT_EVERYTHING_FILES = "javascript.everything.files";

	public static final String JAVASCRIPT_FAST_LOAD = "javascript.fast.load";

	public static final String JAVASCRIPT_LOG_ENABLED = "javascript.log.enabled";

	public static final String JCR_INITIALIZE_ON_STARTUP = "jcr.initialize.on.startup";

	public static final String JCR_JACKRABBIT_CONFIG_FILE_PATH = "jcr.jackrabbit.config.file.path";

	public static final String JCR_JACKRABBIT_CREDENTIALS_PASSWORD = "jcr.jackrabbit.credentials.password";

	public static final String JCR_JACKRABBIT_CREDENTIALS_USERNAME = "jcr.jackrabbit.credentials.username";

	public static final String JCR_JACKRABBIT_REPOSITORY_HOME = "jcr.jackrabbit.repository.home";

	public static final String JCR_JACKRABBIT_REPOSITORY_ROOT = "jcr.jackrabbit.repository.root";

	public static final String JCR_NODE_DOCUMENTLIBRARY = "jcr.node.documentlibrary";

	public static final String JCR_WORKSPACE_NAME = "jcr.workspace.name";

	public static final String JDBC_DEFAULT_LIFERAY_POOL_PROVIDER = "jdbc.default.liferay.pool.provider";

	public static final String JOURNAL_ARTICLE_CHECK_INTERVAL = "journal.article.check.interval";

	public static final String JOURNAL_ARTICLE_COMMENTS_ENABLED = "journal.article.comments.enabled";

	public static final String JOURNAL_ARTICLE_CUSTOM_TOKEN_VALUE = "journal.article.custom.token.value";

	public static final String JOURNAL_ARTICLE_CUSTOM_TOKENS = "journal.article.custom.tokens";

	public static final String JOURNAL_ARTICLE_FORCE_AUTOGENERATE_ID = "journal.article.force.autogenerate.id";

	public static final String JOURNAL_ARTICLE_TOKEN_PAGE_BREAK = "journal.article.token.page.break";

	public static final String JOURNAL_ARTICLE_TYPES = "journal.article.types";

	public static final String JOURNAL_ARTICLE_VIEW_PERMISSION_CHECK_ENABLED = "journal.article.view.permission.check.enabled";

	public static final String JOURNAL_ARTICLES_PAGE_DELTA_VALUES = "journal.articles.page.delta.values";

	public static final String JOURNAL_CONTENT_SEARCH_SHOW_LISTED = "journal.content.search.show.listed";

	public static final String JOURNAL_EMAIL_ARTICLE_ADDED_BODY = "journal.email.article.added.body";

	public static final String JOURNAL_EMAIL_ARTICLE_ADDED_ENABLED = "journal.email.article.added.enabled";

	public static final String JOURNAL_EMAIL_ARTICLE_ADDED_SUBJECT = "journal.email.article.added.subject";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_DENIED_BODY = "journal.email.article.approval.denied.body";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_DENIED_ENABLED = "journal.email.article.approval.denied.enabled";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_DENIED_SUBJECT = "journal.email.article.approval.denied.subject";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_GRANTED_BODY = "journal.email.article.approval.granted.body";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_GRANTED_ENABLED = "journal.email.article.approval.granted.enabled";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_GRANTED_SUBJECT = "journal.email.article.approval.granted.subject";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_REQUESTED_BODY = "journal.email.article.approval.requested.body";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_REQUESTED_ENABLED = "journal.email.article.approval.requested.enabled";

	public static final String JOURNAL_EMAIL_ARTICLE_APPROVAL_REQUESTED_SUBJECT = "journal.email.article.approval.requested.subject";

	public static final String JOURNAL_EMAIL_ARTICLE_REVIEW_BODY = "journal.email.article.review.body";

	public static final String JOURNAL_EMAIL_ARTICLE_REVIEW_ENABLED = "journal.email.article.review.enabled";

	public static final String JOURNAL_EMAIL_ARTICLE_REVIEW_SUBJECT = "journal.email.article.review.subject";

	public static final String JOURNAL_EMAIL_ARTICLE_UPDATED_BODY = "journal.email.article.updated.body";

	public static final String JOURNAL_EMAIL_ARTICLE_UPDATED_ENABLED = "journal.email.article.updated.enabled";

	public static final String JOURNAL_EMAIL_ARTICLE_UPDATED_SUBJECT = "journal.email.article.updated.subject";

	public static final String JOURNAL_EMAIL_FROM_ADDRESS = "journal.email.from.address";

	public static final String JOURNAL_EMAIL_FROM_NAME = "journal.email.from.name";

	public static final String JOURNAL_ERROR_TEMPLATE_FREEMARKER = "journal.error.template.freemarker";

	public static final String JOURNAL_ERROR_TEMPLATE_VELOCITY = "journal.error.template.velocity";

	public static final String JOURNAL_ERROR_TEMPLATE_XSL = "journal.error.template.xsl";

	public static final String JOURNAL_FEED_FORCE_AUTOGENERATE_ID = "journal.feed.force.autogenerate.id";

	public static final String JOURNAL_IMAGE_EXTENSIONS = "journal.image.extensions";

	public static final String JOURNAL_IMAGE_SMALL_MAX_SIZE = "journal.image.small.max.size";

	public static final String JOURNAL_LAR_CREATION_STRATEGY = "journal.lar.creation.strategy";

	public static final String JOURNAL_PUBLISH_TO_LIVE_BY_DEFAULT = "journal.publish.to.live.by.default";

	public static final String JOURNAL_STRUCTURE_FORCE_AUTOGENERATE_ID = "journal.structure.force.autogenerate.id";

	public static final String JOURNAL_SYNC_CONTENT_SEARCH_ON_STARTUP = "journal.sync.content.search.on.startup";

	public static final String JOURNAL_TEMPLATE_FORCE_AUTOGENERATE_ID = "journal.template.force.autogenerate.id";

	public static final String JOURNAL_TEMPLATE_FREEMARKER_RESTRICTED_VARIABLES = "journal.template.freemarker.restricted.variables";

	public static final String JOURNAL_TEMPLATE_LANGUAGE_CONTENT = "journal.template.language.content";

	public static final String JOURNAL_TEMPLATE_LANGUAGE_PARSER = "journal.template.language.parser";

	public static final String JOURNAL_TEMPLATE_LANGUAGE_TYPES = "journal.template.language.types";

	public static final String JOURNAL_TEMPLATE_VELOCITY_RESTRICTED_VARIABLES = "journal.template.velocity.restricted.variables";

	public static final String JOURNAL_TRANSFORMER_LISTENER = "journal.transformer.listener";

	public static final String JPA_CONFIGS = "jpa.configs";

	public static final String JPA_DATABASE_PLATFORM = "jpa.database.platform";

	public static final String JPA_DATABASE_TYPE = "jpa.database.type";

	public static final String JPA_LOAD_TIME_WEAVER = "jpa.load.time.weaver";

	public static final String JPA_PROVIDER = "jpa.provider";

	public static final String JPA_PROVIDER_PROPERTY_PREFIX = "jpa.provider.property.";

	public static final String JSON_SERVICE_INVALID_CLASS_NAMES = "json.service.invalid.class.names";

	public static final String JSP_WRITER_BUFFER_SIZE = "jsp.writer.buffer.size";

	public static final String LAYOUT_CLONE_IMPL = "layout.clone.impl";

	public static final String LAYOUT_COMMENTS_ENABLED = "layout.comments.enabled";

	public static final String LAYOUT_CONFIGURATION_ACTION_DELETE = "layout.configuration.action.delete";

	public static final String LAYOUT_CONFIGURATION_ACTION_UPDATE = "layout.configuration.action.update";

	public static final String LAYOUT_DEFAULT_P_L_RESET = "layout.default.p_l_reset";

	public static final String LAYOUT_DEFAULT_TEMPLATE_ID = "layout.default.template.id";

	public static final String LAYOUT_EDIT_PAGE = "layout.edit.page";

	public static final String LAYOUT_FIRST_PAGEABLE = "layout.first.pageable";

	public static final String LAYOUT_FRIENDLY_URL_KEYWORDS = "layout.friendly.url.keywords";

	public static final String LAYOUT_FRIENDLY_URL_PAGE_NOT_FOUND = "layout.friendly.url.page.not.found";

	public static final String LAYOUT_FRIENDLY_URL_PRIVATE_GROUP_SERVLET_MAPPING = "layout.friendly.url.private.group.servlet.mapping";

	public static final String LAYOUT_FRIENDLY_URL_PRIVATE_USER_SERVLET_MAPPING = "layout.friendly.url.private.user.servlet.mapping";

	public static final String LAYOUT_FRIENDLY_URL_PUBLIC_SERVLET_MAPPING = "layout.friendly.url.public.servlet.mapping";

	public static final String LAYOUT_GUEST_SHOW_MAX_ICON = "layout.guest.show.max.icon";

	public static final String LAYOUT_GUEST_SHOW_MIN_ICON = "layout.guest.show.min.icon";

	public static final String LAYOUT_PARALLEL_RENDER_ENABLE = "layout.parallel.render.enable";

	public static final String LAYOUT_PARENTABLE = "layout.parentable";

	public static final String LAYOUT_REMEMBER_MAXIMIZED_WINDOW_STATE = "layout.remember.maximized.window.state";

	public static final String LAYOUT_SHOW_HTTP_STATUS = "layout.show.http.status";

	public static final String LAYOUT_SHOW_PORTLET_ACCESS_DENIED = "layout.show.portlet.access.denied";

	public static final String LAYOUT_SHOW_PORTLET_INACTIVE = "layout.show.portlet.inactive";

	public static final String LAYOUT_SITEMAPABLE = "layout.sitemapable";

	public static final String LAYOUT_STATIC_PORTLETS_ALL = "layout.static.portlets.all";

	public static final String LAYOUT_STATIC_PORTLETS_END = "layout.static.portlets.end.";

	public static final String LAYOUT_STATIC_PORTLETS_START = "layout.static.portlets.start.";

	public static final String LAYOUT_TEMPLATE_CACHE_ENABLED = "layout.template.cache.enabled";

	public static final String LAYOUT_TYPES = "layout.types";

	public static final String LAYOUT_URL = "layout.url";

	public static final String LAYOUT_URL_FRIENDLIABLE = "layout.url.friendliable";

	public static final String LAYOUT_USER_PRIVATE_LAYOUTS_AUTO_CREATE = "layout.user.private.layouts.auto.create";

	public static final String LAYOUT_USER_PRIVATE_LAYOUTS_ENABLED = "layout.user.private.layouts.enabled";

	public static final String LAYOUT_USER_PRIVATE_LAYOUTS_MODIFIABLE = "layout.user.private.layouts.modifiable";

	public static final String LAYOUT_USER_PRIVATE_LAYOUTS_POWER_USER_REQUIRED = "layout.user.private.layouts.power.user.required";

	public static final String LAYOUT_USER_PUBLIC_LAYOUTS_AUTO_CREATE = "layout.user.public.layouts.auto.create";

	public static final String LAYOUT_USER_PUBLIC_LAYOUTS_ENABLED = "layout.user.public.layouts.enabled";

	public static final String LAYOUT_USER_PUBLIC_LAYOUTS_MODIFIABLE = "layout.user.public.layouts.modifiable";

	public static final String LAYOUT_USER_PUBLIC_LAYOUTS_POWER_USER_REQUIRED = "layout.user.public.layouts.power.user.required";

	public static final String LAYOUT_VIEW_PAGE = "layout.view.page";

	public static final String LDAP_ATTRS_TRANSFORMER_IMPL = "ldap.attrs.transformer.impl";

	public static final String LDAP_AUTH_ENABLED = "ldap.auth.enabled";

	public static final String LDAP_AUTH_METHOD = "ldap.auth.method";

	public static final String LDAP_AUTH_PASSWORD_ENCRYPTION_ALGORITHM = "ldap.auth.password.encryption.algorithm";

	public static final String LDAP_AUTH_PASSWORD_ENCRYPTION_ALGORITHM_TYPES = "ldap.auth.password.encryption.algorithm.types";

	public static final String LDAP_AUTH_REQUIRED = "ldap.auth.required";

	public static final String LDAP_AUTH_SEARCH_FILTER = "ldap.auth.search.filter";

	public static final String LDAP_BASE_DN = "ldap.base.dn";

	public static final String LDAP_BASE_PROVIDER_URL = "ldap.base.provider.url";

	public static final String LDAP_CONTACT_CUSTOM_MAPPINGS = "ldap.contact.custom.mappings";

	public static final String LDAP_CONTACT_MAPPINGS = "ldap.contact.mappings";

	public static final String LDAP_ERROR_PASSWORD_AGE = "ldap.error.password.age";

	public static final String LDAP_ERROR_PASSWORD_EXPIRED = "ldap.error.password.expired";

	public static final String LDAP_ERROR_PASSWORD_HISTORY = "ldap.error.password.history";

	public static final String LDAP_ERROR_PASSWORD_NOT_CHANGEABLE = "ldap.error.password.not.changeable";

	public static final String LDAP_ERROR_PASSWORD_SYNTAX = "ldap.error.password.syntax";

	public static final String LDAP_ERROR_PASSWORD_TRIVIAL = "ldap.error.password.trivial";

	public static final String LDAP_ERROR_USER_LOCKOUT = "ldap.error.user.lockout";

	public static final String LDAP_EXPORT_ENABLED = "ldap.export.enabled";

	public static final String LDAP_FACTORY_INITIAL = "ldap.factory.initial";

	public static final String LDAP_GROUP_DEFAULT_OBJECT_CLASSES = "ldap.group.default.object.classes";

	public static final String LDAP_GROUP_MAPPINGS = "ldap.group.mappings";

	public static final String LDAP_GROUPS_DN = "ldap.groups.dn";

	public static final String LDAP_IMPORT_CREATE_ROLE_PER_GROUP = "ldap.import.create.role.per.group";

	public static final String LDAP_IMPORT_ENABLED = "ldap.import.enabled";

	public static final String LDAP_IMPORT_GROUP_SEARCH_FILTER = "ldap.import.group.search.filter";

	public static final String LDAP_IMPORT_INTERVAL = "ldap.import.interval";

	public static final String LDAP_IMPORT_METHOD = "ldap.import.method";

	public static final String LDAP_IMPORT_ON_STARTUP = "ldap.import.on.startup";

	public static final String LDAP_IMPORT_USER_SEARCH_FILTER = "ldap.import.user.search.filter";

	public static final String LDAP_PAGE_SIZE = "ldap.page.size";

	public static final String LDAP_PASSWORD_POLICY_ENABLED = "ldap.password.policy.enabled";

	public static final String LDAP_RANGE_SIZE = "ldap.range.size";

	public static final String LDAP_REFERRAL = "ldap.referral";

	public static final String LDAP_SECURITY_CREDENTIALS = "ldap.security.credentials";

	public static final String LDAP_SECURITY_PRINCIPAL = "ldap.security.principal";

	public static final String LDAP_SERVER_NAME = "ldap.server.name";

	public static final String LDAP_USER_CUSTOM_MAPPINGS = "ldap.user.custom.mappings";

	public static final String LDAP_USER_DEFAULT_OBJECT_CLASSES = "ldap.user.default.object.classes";

	public static final String LDAP_USER_IMPL = "ldap.user.impl";

	public static final String LDAP_USER_MAPPINGS = "ldap.user.mappings";

	public static final String LDAP_USERS_DN = "ldap.users.dn";

	public static final String LIBRARY_DOWNLOAD_URL = "library.download.url.";

	public static final String LIFERAY_HOME = "liferay.home";

	public static final String LIVE_USERS_ENABLED = "live.users.enabled";

	public static final String LOCALE_DEFAULT_REQUEST = "locale.default.request";

	public static final String LOCALE_PREPEND_FRIENDLY_URL_STYLE = "locale.prepend.friendly.url.style";

	public static final String LOCALES = "locales";

	public static final String LOGIN_CREATE_ACCOUNT_ALLOW_CUSTOM_PASSWORD = "login.create.account.allow.custom.password";

	public static final String LOGIN_EVENTS_POST = "login.events.post";

	public static final String LOGIN_EVENTS_PRE = "login.events.pre";

	public static final String LOGOUT_EVENTS_POST = "logout.events.post";

	public static final String LOGOUT_EVENTS_PRE = "logout.events.pre";

	public static final String LOOK_AND_FEEL_MODIFIABLE = "look.and.feel.modifiable";

	public static final String LUCENE_ANALYZER = "lucene.analyzer";

	public static final String LUCENE_BUFFER_SIZE = "lucene.buffer.size";

	public static final String LUCENE_COMMIT_BATCH_SIZE = "lucene.commit.batch.size";

	public static final String LUCENE_COMMIT_TIME_INTERVAL = "lucene.commit.time.interval";

	public static final String LUCENE_DIR = "lucene.dir";

	public static final String LUCENE_FILE_EXTRACTOR = "lucene.file.extractor";

	public static final String LUCENE_FILE_EXTRACTOR_REGEXP_STRIP = "lucene.file.extractor.regexp.strip";

	public static final String LUCENE_MERGE_FACTOR = "lucene.merge.factor";

	public static final String LUCENE_OPTIMIZE_INTERVAL = "lucene.optimize.interval";

	public static final String LUCENE_REPLICATE_WRITE = "lucene.replicate.write";

	public static final String LUCENE_STORE_JDBC_AUTO_CLEAN_UP_ENABLED = "lucene.store.jdbc.auto.clean.up.enabled";

	public static final String LUCENE_STORE_JDBC_AUTO_CLEAN_UP_INTERVAL = "lucene.store.jdbc.auto.clean.up.interval";

	public static final String LUCENE_STORE_JDBC_DIALECT = "lucene.store.jdbc.dialect.";

	public static final String LUCENE_STORE_TYPE = "lucene.store.type";

	public static final String MAIL_AUDIT_TRAIL = "mail.audit.trail";

	public static final String MAIL_HOOK_CYRUS_ADD_USER = "mail.hook.cyrus.add.user";

	public static final String MAIL_HOOK_CYRUS_DELETE_USER = "mail.hook.cyrus.delete.user";

	public static final String MAIL_HOOK_CYRUS_HOME = "mail.hook.cyrus.home";

	public static final String MAIL_HOOK_FUSEMAIL_ACCOUNT_TYPE = "mail.hook.fusemail.account.type";

	public static final String MAIL_HOOK_FUSEMAIL_GROUP_PARENT = "mail.hook.fusemail.group.parent";

	public static final String MAIL_HOOK_FUSEMAIL_PASSWORD = "mail.hook.fusemail.password";

	public static final String MAIL_HOOK_FUSEMAIL_URL = "mail.hook.fusemail.url";

	public static final String MAIL_HOOK_FUSEMAIL_USERNAME = "mail.hook.fusemail.username";

	public static final String MAIL_HOOK_IMPL = "mail.hook.impl";

	public static final String MAIL_HOOK_SENDMAIL_ADD_USER = "mail.hook.sendmail.add.user";

	public static final String MAIL_HOOK_SENDMAIL_CHANGE_PASSWORD = "mail.hook.sendmail.change.password";

	public static final String MAIL_HOOK_SENDMAIL_DELETE_USER = "mail.hook.sendmail.delete.user";

	public static final String MAIL_HOOK_SENDMAIL_HOME = "mail.hook.sendmail.home";

	public static final String MAIL_HOOK_SENDMAIL_VIRTUSERTABLE = "mail.hook.sendmail.virtusertable";

	public static final String MAIL_HOOK_SENDMAIL_VIRTUSERTABLE_REFRESH = "mail.hook.sendmail.virtusertable.refresh";

	public static final String MAIL_HOOK_SHELL_SCRIPT = "mail.hook.shell.script";

	public static final String MAIL_MX_UPDATE = "mail.mx.update";

	public static final String MAIL_SESSION_MAIL = "mail.session.mail";

	public static final String MAIL_SESSION_MAIL_ADVANCED_PROPERTIES = "mail.session.mail.advanced.properties";

	public static final String MAIL_SESSION_MAIL_POP3_HOST = "mail.session.mail.pop3.host";

	public static final String MAIL_SESSION_MAIL_POP3_PASSWORD = "mail.session.mail.pop3.password";

	public static final String MAIL_SESSION_MAIL_POP3_PORT = "mail.session.mail.pop3.port";

	public static final String MAIL_SESSION_MAIL_POP3_USER = "mail.session.mail.pop3.user";

	public static final String MAIL_SESSION_MAIL_SMTP_HOST = "mail.session.mail.smtp.host";

	public static final String MAIL_SESSION_MAIL_SMTP_PASSWORD = "mail.session.mail.smtp.password";

	public static final String MAIL_SESSION_MAIL_SMTP_PORT = "mail.session.mail.smtp.port";

	public static final String MAIL_SESSION_MAIL_SMTP_USER = "mail.session.mail.smtp.user";

	public static final String MAIL_SESSION_MAIL_STORE_PROTOCOL = "mail.session.mail.store.protocol";

	public static final String MAIL_SESSION_MAIL_TRANSPORT_PROTOCOL = "mail.session.mail.transport.protocol";

	public static final String MESSAGE_BOARDS_ALLOW_ANONYMOUS_POSTING = "message.boards.anonymous.posting.enabled";

	public static final String MESSAGE_BOARDS_ANONYMOUS_POSTING_ENABLED = "message.boards.anonymous.posting.enabled";

	public static final String MESSAGE_BOARDS_EMAIL_FROM_ADDRESS = "message.boards.email.from.address";

	public static final String MESSAGE_BOARDS_EMAIL_FROM_NAME = "message.boards.email.from.name";

	public static final String MESSAGE_BOARDS_EMAIL_HTML_FORMAT = "message.boards.email.html.format";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_BODY = "message.boards.email.message.added.body";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_ENABLED = "message.boards.email.message.added.enabled";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_SIGNATURE = "message.boards.email.message.added.signature";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_ADDED_SUBJECT_PREFIX = "message.boards.email.message.added.subject.prefix";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_BODY = "message.boards.email.message.updated.body";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_ENABLED = "message.boards.email.message.updated.enabled";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_SIGNATURE = "message.boards.email.message.updated.signature";

	public static final String MESSAGE_BOARDS_EMAIL_MESSAGE_UPDATED_SUBJECT_PREFIX = "message.boards.email.message.updated.subject.prefix";

	public static final String MESSAGE_BOARDS_EXPIRE_BAN_INTERVAL = "message.boards.expire.ban.interval";

	public static final String MESSAGE_BOARDS_EXPIRE_BAN_JOB_INTERVAL = "message.boards.expire.ban.job.interval";

	public static final String MESSAGE_BOARDS_PINGBACK_ENABLED = "message.boards.pingback.enabled";

	public static final String MESSAGE_BOARDS_RSS_ABSTRACT_LENGTH = "message.boards.rss.abstract.length";

	public static final String MESSAGE_BOARDS_THREAD_PREVIOUS_AND_NEXT_NAVIGATION_ENABLED = "message.boards.thread.previous.and.next.navigation.enabled";

	public static final String MESSAGE_BOARDS_THREAD_VIEWS = "message.boards.thread.views";

	public static final String MESSAGE_BOARDS_THREAD_VIEWS_DEFAULT = "message.boards.thread.views.default";

	public static final String MIME_TYPES_CONTENT_DISPOSITION_INLINE = "mime.types.content.disposition.inline";

	public static final String MINIFIER_INLINE_CONTENT_CACHE_SIZE = "minifier.inline.content.cache.size";

	public static final String MINIFIER_INLINE_CONTENT_CACHE_SKIP_CSS = "minifier.inline.content.cache.skip.css";

	public static final String MINIFIER_INLINE_CONTENT_CACHE_SKIP_JAVASCRIPT = "minifier.inline.content.cache.skip.javascript";

	public static final String MODEL_HINTS_CONFIGS = "model.hints.configs";

	public static final String MONITORING_DATA_SAMPLE_THREAD_LOCAL = "monitoring.data.sample.thread.local";

	public static final String MONITORING_PORTAL_REQUEST = "monitoring.portal.request";

	public static final String MONITORING_PORTLET_ACTION_REQUEST = "monitoring.portlet.action.request";

	public static final String MONITORING_PORTLET_EVENT_REQUEST = "monitoring.portlet.event.request";

	public static final String MONITORING_PORTLET_RENDER_REQUEST = "monitoring.portlet.render.request";

	public static final String MONITORING_PORTLET_RESOURCE_REQUEST = "monitoring.portlet.resource.request";

	public static final String MONITORING_SHOW_PER_REQUEST_DATA_SAMPLE = "monitoring.show.per.request.data.sample";

	public static final String MSN_LOGIN = "msn.login";

	public static final String MSN_PASSWORD = "msn.password";

	public static final String MY_PLACES_DISPLAY_STYLE = "my.places.display.style";

	public static final String MY_PLACES_MAX_ELEMENTS = "my.places.max.elements";

	public static final String MY_PLACES_SHOW_COMMUNITY_PRIVATE_SITES_WITH_NO_LAYOUTS = "my.places.show.community.private.sites.with.no.layouts";

	public static final String MY_PLACES_SHOW_COMMUNITY_PUBLIC_SITES_WITH_NO_LAYOUTS = "my.places.show.community.public.sites.with.no.layouts";

	public static final String MY_PLACES_SHOW_ORGANIZATION_PRIVATE_SITES_WITH_NO_LAYOUTS = "my.places.show.organization.private.sites.with.no.layouts";

	public static final String MY_PLACES_SHOW_ORGANIZATION_PUBLIC_SITES_WITH_NO_LAYOUTS = "my.places.show.organization.public.sites.with.no.layouts";

	public static final String MY_PLACES_SHOW_USER_PRIVATE_SITES_WITH_NO_LAYOUTS = "my.places.show.user.private.sites.with.no.layouts";

	public static final String MY_PLACES_SHOW_USER_PUBLIC_SITES_WITH_NO_LAYOUTS = "my.places.show.user.public.sites.with.no.layouts";

	public static final String NESTED_PORTLETS_LAYOUT_TEMPLATE_DEFAULT = "nested.portlets.layout.template.default";

	public static final String NESTED_PORTLETS_LAYOUT_TEMPLATE_UNSUPPORTED = "nested.portlets.layout.template.unsupported";

	public static final String NETVIBES_SERVLET_MAPPING = "netvibes.servlet.mapping";

	public static final String NTLM_AUTH_ENABLED = "ntlm.auth.enabled";

	public static final String NTLM_DOMAIN = "ntlm.auth.domain";

	public static final String NTLM_DOMAIN_CONTROLLER = "ntlm.auth.domain.controller";

	public static final String NTLM_DOMAIN_CONTROLLER_NAME = "ntlm.auth.domain.controller.name";

	public static final String NTLM_SERVICE_ACCOUNT = "ntlm.auth.service.account";

	public static final String NTLM_SERVICE_PASSWORD = "ntlm.auth.service.password";

	public static final String OMNIADMIN_USERS = "omniadmin.users";

	public static final String OPEN_ID_AUTH_ENABLED = "open.id.auth.enabled";

	public static final String OPEN_SSO_AUTH_ENABLED = "open.sso.auth.enabled";

	public static final String OPEN_SSO_EMAIL_ADDRESS_ATTR = "open.sso.email.address.attr";

	public static final String OPEN_SSO_FIRST_NAME_ATTR = "open.sso.first.name.attr";

	public static final String OPEN_SSO_LAST_NAME_ATTR = "open.sso.last.name.attr";

	public static final String OPEN_SSO_LDAP_IMPORT_ENABLED = "open.sso.ldap.import.enabled";

	public static final String OPEN_SSO_LOGIN_URL = "open.sso.login.url";

	public static final String OPEN_SSO_LOGOUT_URL = "open.sso.logout.url";

	public static final String OPEN_SSO_SCREEN_NAME_ATTR = "open.sso.screen.name.attr";

	public static final String OPEN_SSO_SERVICE_URL = "open.sso.service.url";

	public static final String OPENOFFICE_CACHE_ENABLED = "openoffice.cache.enabled";

	public static final String OPENOFFICE_SERVER_ENABLED = "openoffice.server.enabled";

	public static final String OPENOFFICE_SERVER_HOST = "openoffice.server.host";

	public static final String OPENOFFICE_SERVER_PORT = "openoffice.server.port";

	public static final String ORGANIZATIONS_ASSIGNMENT_AUTO = "organizations.assignment.auto";

	public static final String ORGANIZATIONS_ASSIGNMENT_STRICT = "organizations.assignment.strict";

	public static final String ORGANIZATIONS_CHILDREN_TYPES = "organizations.children.types";

	public static final String ORGANIZATIONS_COUNTRY_ENABLED = "organizations.country.enabled";

	public static final String ORGANIZATIONS_COUNTRY_REQUIRED = "organizations.country.required";

	public static final String ORGANIZATIONS_FORM_ADD_IDENTIFICATION = "organizations.form.add.identification";

	public static final String ORGANIZATIONS_FORM_ADD_MAIN = "organizations.form.add.main";

	public static final String ORGANIZATIONS_FORM_ADD_MISCELLANEOUS = "organizations.form.add.miscellaneous";

	public static final String ORGANIZATIONS_FORM_UPDATE_IDENTIFICATION = "organizations.form.update.identification";

	public static final String ORGANIZATIONS_FORM_UPDATE_MAIN = "organizations.form.update.main";

	public static final String ORGANIZATIONS_FORM_UPDATE_MISCELLANEOUS = "organizations.form.update.miscellaneous";

	public static final String ORGANIZATIONS_MEMBERSHIP_STRICT = "organizations.membership.strict";

	public static final String ORGANIZATIONS_ROOTABLE = "organizations.rootable";

	public static final String ORGANIZATIONS_SEARCH_WITH_INDEX = "organizations.search.with.index";

	public static final String ORGANIZATIONS_TYPES = "organizations.types";

	public static final String ORGANIZATIONS_USER_GROUP_MEMBERSHIP_ENABLED = "organizations.user.group.membership.enabled";

	public static final String PASSWORDS_DEFAULT_POLICY_NAME = "passwords.default.policy.name";

	public static final String PASSWORDS_DIGEST_ENCODING = "passwords.digest.encoding";

	public static final String PASSWORDS_ENCRYPTION_ALGORITHM = "passwords.encryption.algorithm";

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_LOWERCASE = "passwords.passwordpolicytoolkit.charset.lowercase";

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_NUMBERS = "passwords.passwordpolicytoolkit.charset.numbers";

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_SYMBOLS = "passwords.passwordpolicytoolkit.charset.symbols";

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_CHARSET_UPPERCASE = "passwords.passwordpolicytoolkit.charset.uppercase";

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_GENERATOR = "passwords.passwordpolicytoolkit.generator";

	public static final String PASSWORDS_PASSWORDPOLICYTOOLKIT_STATIC = "passwords.passwordpolicytoolkit.static";

	public static final String PASSWORDS_REGEXPTOOLKIT_CHARSET = "passwords.regexptoolkit.charset";

	public static final String PASSWORDS_REGEXPTOOLKIT_LENGTH = "passwords.regexptoolkit.length";

	public static final String PASSWORDS_REGEXPTOOLKIT_PATTERN = "passwords.regexptoolkit.pattern";

	public static final String PASSWORDS_TOOLKIT = "passwords.toolkit";

	public static final String PERMISSIONS_CHECKER = "permissions.checker";

	public static final String PERMISSIONS_LIST_FILTER = "permissions.list.filter";

	public static final String PERMISSIONS_OBJECT_BLOCKING_CACHE = "permissions.object.blocking.cache";

	public static final String PERMISSIONS_THREAD_LOCAL_CACHE_MAX_SIZE = "permissions.thread.local.cache.max.size";

	public static final String PERMISSIONS_USER_CHECK_ALGORITHM = "permissions.user.check.algorithm";

	public static final String PERMISSIONS_VIEW_DYNAMIC_INHERITANCE = "permissions.view.dynamic.inheritance";

	public static final String PERSISTENCE_PROVIDER = "persistence.provider";

	public static final String PLUGIN_NOTIFICATIONS_ENABLED = "plugin.notifications.enabled";

	public static final String PLUGIN_NOTIFICATIONS_PACKAGES_IGNORED = "plugin.notifications.packages.ignored";

	public static final String PLUGIN_REPOSITORIES_TRUSTED = "plugin.repositories.trusted";

	public static final String PLUGIN_REPOSITORIES_UNTRUSTED = "plugin.repositories.untrusted";

	public static final String PLUGIN_TYPES = "plugin.types";

	public static final String POLLER_REQUEST_TIMEOUT = "poller.request.timeout";

	public static final String POP_SERVER_NOTIFICATIONS_ENABLED = "pop.server.notifications.enabled";

	public static final String POP_SERVER_NOTIFICATIONS_INTERVAL = "pop.server.notifications.interval";

	public static final String POP_SERVER_SUBDOMAIN = "pop.server.subdomain";

	public static final String PORTAL_CTX = "portal.ctx";

	public static final String PORTAL_IMPERSONATION_ENABLE = "portal.impersonation.enable";

	public static final String PORTAL_JAAS_ENABLE = "portal.jaas.enable";

	public static final String PORTAL_JAAS_IMPL = "portal.jaas.impl";

	public static final String PORTAL_JAAS_STRICT_PASSWORD = "portal.jaas.strict.password";

	public static final String PORTAL_SECURITY_MANAGER_ENABLE = "portal.security.manager.enable";

	public static final String PORTLET_ADD_DEFAULT_RESOURCE_CHECK_ENABLED = "portlet.add.default.resource.check.enabled";

	public static final String PORTLET_ADD_DEFAULT_RESOURCE_CHECK_WHITELIST = "portlet.add.default.resource.check.whitelist";

	public static final String PORTLET_ADD_DEFAULT_RESOURCE_CHECK_WHITELIST_ACTIONS = "portlet.add.default.resource.check.whitelist.actions";

	public static final String PORTLET_CSS_ENABLED = "portlet.css.enabled";

	public static final String PORTLET_EVENT_DISTRIBUTION = "portlet.event.distribution";

	public static final String PORTLET_PUBLIC_RENDER_PARAMETER_DISTRIBUTION = "portlet.public.render.parameter.distribution";

	public static final String PORTLET_RESOURCE_ID_BANNED_PATHS_REGEXP = "portlet.resource.id.banned.paths.regexp";

	public static final String PORTLET_URL_ANCHOR_ENABLE = "portlet.url.anchor.enable";

	public static final String PORTLET_URL_APPEND_PARAMETERS = "portlet.url.append.parameters";

	public static final String PORTLET_URL_ESCAPE_XML = "portlet.url.escape.xml";

	public static final String PORTLET_VIRTUAL_PATH = "portlet.virtual.path";

	public static final String PORTLET_XML_VALIDATE = "portlet.xml.validate";

	public static final String PREFERENCE_VALIDATE_ON_STARTUP = "preference.validate.on.startup";

	public static final String REDIRECT_URL_DOMAINS_ALLOWED = "redirect.url.domains.allowed";

	public static final String REDIRECT_URL_IPS_ALLOWED = "redirect.url.ips.allowed";

	public static final String REDIRECT_URL_SECURITY_MODE = "redirect.url.security.mode";

	public static final String RELEASE_INFO_BUILD_NUMBER = "release.info.build.number";

	public static final String RELEASE_INFO_PREVIOUS_BUILD_NUMBER = "release.info.previous.build.number";

	public static final String REQUEST_HEADER_AUTH_IMPORT_FROM_LDAP = "request.header.auth.import.from.ldap";

	public static final String REQUEST_SHARED_ATTRIBUTES = "request.shared.attributes";

	public static final String RESOURCE_ACTIONS_CONFIGS = "resource.actions.configs";

	public static final String RESOURCE_ACTIONS_READ_PORTLET_RESOURCES = "resource.actions.read.portlet.resources";

	public static final String RESOURCE_REPOSITORIES_ROOT = "resource.repositories.root";

	public static final String ROLES_COMMUNITY_SUBTYPES = "roles.community.subtypes";

	public static final String ROLES_ORGANIZATION_SUBTYPES = "roles.organization.subtypes";

	public static final String ROLES_REGULAR_SUBTYPES = "roles.regular.subtypes";

	public static final String SANDBOX_DEPLOY_DIR = "sandbox.deploy.dir";

	public static final String SANDBOX_DEPLOY_ENABLED = "sandbox.deploy.enabled";

	public static final String SANDBOX_DEPLOY_INTERVAL = "sandbox.deploy.interval";

	public static final String SANDBOX_DEPLOY_LISTENERS = "sandbox.deploy.listeners";

	public static final String SANITIZER_IMPL = "sanitizer.impl";

	public static final String SC_IMAGE_MAX_SIZE = "sc.image.max.size";

	public static final String SC_IMAGE_THUMBNAIL_MAX_HEIGHT = "sc.image.thumbnail.max.height";

	public static final String SC_IMAGE_THUMBNAIL_MAX_WIDTH = "sc.image.thumbnail.max.width";

	public static final String SC_PRODUCT_COMMENTS_ENABLED = "sc.product.comments.enabled";

	public static final String SCHEDULER_CLASSES = "scheduler.classes";

	public static final String SCHEDULER_ENABLED = "scheduler.enabled";

	public static final String SCHEMA_RUN_ENABLED = "schema.run.enabled";

	public static final String SCHEMA_RUN_MINIMAL = "schema.run.minimal";

	public static final String SCRIPTING_FORBIDDEN_CLASSES = "scripting.forbidden.classes";

	public static final String SEARCH_CONTAINER_PAGE_DELTA_VALUES = "search.container.page.delta.values";

	public static final String SEARCH_CONTAINER_PAGE_ITERATOR_MAX_PAGES = "search.container.page.iterator.max.pages";

	public static final String SEARCH_CONTAINER_SHOW_PAGINATION_BOTTOM = "search.container.show.pagination.bottom";

	public static final String SEARCH_CONTAINER_SHOW_PAGINATION_TOP = "search.container.show.pagination.top";

	public static final String SERVICE_BUILDER_SERVICE_READ_ONLY_PREFIXES = "service.builder.service.read.only.prefixes";

	public static final String SERVLET_SERVICE_EVENTS_POST = "servlet.service.events.post";

	public static final String SERVLET_SERVICE_EVENTS_PRE = "servlet.service.events.pre";

	public static final String SERVLET_SERVICE_EVENTS_PRE_ERROR_PAGE = "servlet.service.events.pre.error.page";

	public static final String SERVLET_SESSION_CREATE_EVENTS = "servlet.session.create.events";

	public static final String SERVLET_SESSION_DESTROY_EVENTS = "servlet.session.destroy.events";

	public static final String SESSION_COOKIE_DOMAIN = "session.cookie.domain";

	public static final String SESSION_DISABLED = "session.disabled";

	public static final String SESSION_ENABLE_PERSISTENT_COOKIES = "session.enable.persistent.cookies";

	public static final String SESSION_ENABLE_PHISHING_PROTECTION = "session.enable.phishing.protection";

	public static final String SESSION_ENABLE_URL_WITH_SESSION_ID = "session.enable.url.with.session.id";

	public static final String SESSION_PHISHING_PROTECTED_ATTRIBUTES = "session.phishing.protected.attributes";

	public static final String SESSION_SHARED_ATTRIBUTES = "session.shared.attributes";

	public static final String SESSION_SHARED_ATTRIBUTES_EXCLUDES = "session.shared.attributes.excludes";

	public static final String SESSION_STORE_PASSWORD = "session.store.password";

	public static final String SESSION_TEST_COOKIE_SUPPORT = "session.test.cookie.support";

	public static final String SESSION_TIMEOUT = "session.timeout";

	public static final String SESSION_TIMEOUT_AUTO_EXTEND = "session.timeout.auto.extend";

	public static final String SESSION_TIMEOUT_REDIRECT_ON_EXPIRE = "session.timeout.redirect.on.expire";

	public static final String SESSION_TIMEOUT_WARNING = "session.timeout.warning";

	public static final String SESSION_TRACKER_FRIENDLY_PATHS_ENABLED = "session.tracker.friendly.paths.enabled";

	public static final String SESSION_TRACKER_IGNORE_PATHS = "session.tracker.ignore.paths";

	public static final String SESSION_TRACKER_MEMORY_ENABLED = "session.tracker.memory.enabled";

	public static final String SESSION_TRACKER_PERSISTENCE_ENABLED = "session.tracker.persistence.enabled";

	public static final String SHARD_AVAILABLE_NAMES = "shard.available.names";

	public static final String SHARD_DEFAULT_NAME = "shard.default.name";

	public static final String SHARD_SELECTOR = "shard.selector";

	public static final String SHAREPOINT_STORAGE_CLASS = "sharepoint.storage.class";

	public static final String SHAREPOINT_STORAGE_TOKENS = "sharepoint.storage.tokens";
	
	//Chris Jurado 3 August 2011  
	public static final String SHIBBOLETH_AUTH_ENABLED = "shibboleth.auth.enabled";
	
	public static final String SHIBBOLETH_USER_HEADER = "shibboleth.user.header";
	//
	
	public static final String SHOPPING_CART_MIN_QTY_MULTIPLE = "shopping.cart.min.qty.multiple";

	public static final String SHOPPING_CATEGORY_FORWARD_TO_CART = "shopping.category.forward.to.cart";

	public static final String SHOPPING_CATEGORY_SHOW_SPECIAL_ITEMS = "shopping.category.show.special.items";

	public static final String SHOPPING_EMAIL_FROM_ADDRESS = "shopping.email.from.address";

	public static final String SHOPPING_EMAIL_FROM_NAME = "shopping.email.from.name";

	public static final String SHOPPING_EMAIL_ORDER_CONFIRMATION_BODY = "shopping.email.order.confirmation.body";

	public static final String SHOPPING_EMAIL_ORDER_CONFIRMATION_ENABLED = "shopping.email.order.confirmation.enabled";

	public static final String SHOPPING_EMAIL_ORDER_CONFIRMATION_SUBJECT = "shopping.email.order.confirmation.subject";

	public static final String SHOPPING_EMAIL_ORDER_SHIPPING_BODY = "shopping.email.order.shipping.body";

	public static final String SHOPPING_EMAIL_ORDER_SHIPPING_ENABLED = "shopping.email.order.shipping.enabled";

	public static final String SHOPPING_EMAIL_ORDER_SHIPPING_SUBJECT = "shopping.email.order.shipping.subject";

	public static final String SHOPPING_IMAGE_EXTENSIONS = "shopping.image.extensions";

	public static final String SHOPPING_IMAGE_LARGE_MAX_SIZE = "shopping.image.large.max.size";

	public static final String SHOPPING_IMAGE_MEDIUM_MAX_SIZE = "shopping.image.medium.max.size";

	public static final String SHOPPING_IMAGE_SMALL_MAX_SIZE = "shopping.image.small.max.size";

	public static final String SHOPPING_ITEM_SHOW_AVAILABILITY = "shopping.item.show.availability";

	public static final String SHOPPING_ORDER_COMMENTS_ENABLED = "shopping.order.comments.enabled";

	public static final String SHUTDOWN_PROGRAMMATICALLY_EXIT = "shutdown.programmatically.exit";

	public static final String SITEMINDER_AUTH_ENABLED = "siteminder.auth.enabled";

	public static final String SITEMINDER_IMPORT_FROM_LDAP = "siteminder.import.from.ldap";

	public static final String SITEMINDER_USER_HEADER = "siteminder.user.header";

	public static final String SOCIAL_BOOKMARK_POST_URL = "social.bookmark.post.url";

	public static final String SOCIAL_BOOKMARK_TYPES = "social.bookmark.types";

	public static final String SOCIAL_EQUITY_EQUITY_LOG_CHECK_INTERVAL = "social.equity.equity.log.check.interval";

	public static final String SOCIAL_EQUITY_EQUITY_LOG_ENABLED = "social.equity.equity.log.enabled";

	public static final String SOURCE_FORGE_MIRRORS = "source.forge.mirrors";

	public static final String SPRING_CONFIGS = "spring.configs";

	public static final String SPRING_HIBERNATE_DATA_SOURCE = "spring.hibernate.data.source";

	public static final String SPRING_HIBERNATE_SESSION_DELEGATED = "spring.hibernate.session.delegated";

	public static final String SPRING_HIBERNATE_SESSION_FACTORY = "spring.hibernate.session.factory";

	public static final String SQL_DATA_COM_LIFERAY_PORTAL_MODEL_COUNTRY_COUNTRY_ID = "sql.data.com.liferay.portal.model.Country.country.id";

	public static final String SQL_DATA_COM_LIFERAY_PORTAL_MODEL_LISTTYPE_ACCOUNT_ADDRESS = "sql.data.com.liferay.portal.model.ListType.account.address";

	public static final String SQL_DATA_COM_LIFERAY_PORTAL_MODEL_LISTTYPE_ACCOUNT_EMAIL_ADDRESS = "sql.data.com.liferay.portal.model.ListType.account.email.address";

	public static final String SQL_DATA_COM_LIFERAY_PORTAL_MODEL_LISTTYPE_CONTACT_EMAIL_ADDRESS = "sql.data.com.liferay.portal.model.ListType.contact.email.address";

	public static final String SQL_DATA_COM_LIFERAY_PORTAL_MODEL_LISTTYPE_ORGANIZATION_STATUS = "sql.data.com.liferay.portal.model.ListType.organization.status";

	public static final String SQL_DATA_COM_LIFERAY_PORTAL_MODEL_REGION_REGION_ID = "sql.data.com.liferay.portal.model.Region.region.id";

	public static final String SQL_DATA_MAX_PARAMETERS = "sql.data.max.parameters";

	public static final String STRIP_IGNORE_PATHS = "strip.ignore.paths";

	public static final String STRUTS_PORTLET_REQUEST_PROCESSOR = "struts.portlet.request.processor";

	public static final String SYSTEM_COMMUNITY_ROLES = "system.community.roles";

	public static final String SYSTEM_GROUPS = "system.groups";

	public static final String SYSTEM_ORGANIZATION_ROLES = "system.organization.roles";

	public static final String SYSTEM_ROLES = "system.roles";

	public static final String TAGS_COMPILER_ENABLED = "tags.compiler.enabled";

	public static final String TASKS_DEFAULT_ROLE_NAMES = "tasks.default.role.names";

	public static final String TASKS_DEFAULT_STAGES = "tasks.default.stages";

	public static final String TCK_URL = "tck.url";

	public static final String TERMS_OF_USE_JOURNAL_ARTICLE_GROUP_ID = "terms.of.use.journal.article.group.id";

	public static final String TERMS_OF_USE_JOURNAL_ARTICLE_ID = "terms.of.use.journal.article.id";

	public static final String TERMS_OF_USE_REQUIRED = "terms.of.use.required";

	public static final String THEME_CSS_FAST_LOAD = "theme.css.fast.load";

	public static final String THEME_IMAGES_FAST_LOAD = "theme.images.fast.load";

	public static final String THEME_LOADER_NEW_THEME_ID_ON_IMPORT = "theme.loader.new.theme.id.on.import";

	public static final String THEME_LOADER_STORAGE_PATH = "theme.loader.storage.path";

	public static final String THEME_PORTLET_DECORATE_DEFAULT = "theme.portlet.decorate.default";

	public static final String THEME_PORTLET_SHARING_DEFAULT = "theme.portlet.sharing.default";

	public static final String THEME_SHORTCUT_ICON = "theme.shortcut.icon";

	public static final String THEME_SYNC_ON_GROUP = "theme.sync.on.group";

	public static final String THEME_VIRTUAL_PATH = "theme.virtual.path";

	public static final String TIME_ZONES = "time.zones";

	public static final String TRANSACTION_ISOLATION_PORTAL = "transaction.isolation.portal";

	public static final String TRANSACTION_MANAGER_IMPL = "transaction.manager.impl";

	public static final String TRANSACTIONAL_CACHE_ENABLED = "transactional.cache.enable";

	public static final String TRANSLATOR_DEFAULT_LANGUAGES = "translator.default.languages";

	public static final String UPGRADE_PROCESSES = "upgrade.processes";

	public static final String UPLOAD_SERVLET_REQUEST_IMPL_MAX_SIZE = "com.liferay.portal.upload.UploadServletRequestImpl.max.size";

	public static final String UPLOAD_SERVLET_REQUEST_IMPL_TEMP_DIR = "com.liferay.portal.upload.UploadServletRequestImpl.temp.dir";

	public static final String USERS_DELETE = "users.delete";

	public static final String USERS_EMAIL_ADDRESS_AUTO_SUFFIX = "users.email.address.auto.suffix";

	public static final String USERS_EMAIL_ADDRESS_GENERATOR = "users.email.address.generator";

	public static final String USERS_EMAIL_ADDRESS_REQUIRED = "users.email.address.required";

	public static final String USERS_EXPORT_CSV_FIELDS = "users.export.csv.fields";

	public static final String USERS_FORM_ADD_IDENTIFICATION = "users.form.add.identification";

	public static final String USERS_FORM_ADD_MAIN = "users.form.add.main";

	public static final String USERS_FORM_ADD_MISCELLANEOUS = "users.form.add.miscellaneous";

	public static final String USERS_FORM_MY_ACCOUNT_IDENTIFICATION = "users.form.my.account.identification";

	public static final String USERS_FORM_MY_ACCOUNT_MAIN = "users.form.my.account.main";

	public static final String USERS_FORM_MY_ACCOUNT_MISCELLANEOUS = "users.form.my.account.miscellaneous";

	public static final String USERS_FORM_UPDATE_IDENTIFICATION = "users.form.update.identification";

	public static final String USERS_FORM_UPDATE_MAIN = "users.form.update.main";

	public static final String USERS_FORM_UPDATE_MISCELLANEOUS = "users.form.update.miscellaneous";

	public static final String USERS_FULL_NAME_GENERATOR = "users.full.name.generator";

	public static final String USERS_FULL_NAME_VALIDATOR = "users.full.name.validator";

	public static final String USERS_IMAGE_MAX_HEIGHT = "users.image.max.height";

	public static final String USERS_IMAGE_MAX_SIZE = "users.image.max.size";

	public static final String USERS_IMAGE_MAX_WIDTH = "users.image.max.width";

	public static final String USERS_REMINDER_QUERIES_CUSTOM_QUESTION_ENABLED = "users.reminder.queries.custom.question.enabled";

	public static final String USERS_REMINDER_QUERIES_ENABLED = "users.reminder.queries.enabled";

	public static final String USERS_REMINDER_QUERIES_QUESTIONS = "users.reminder.queries.questions";

	public static final String USERS_REMINDER_QUERIES_REQUIRED = "users.reminder.queries.required";

	public static final String USERS_SCREEN_NAME_ALLOW_NUMERIC = "users.screen.name.allow.numeric";

	public static final String USERS_SCREEN_NAME_ALWAYS_AUTOGENERATE = "users.screen.name.always.autogenerate";

	public static final String USERS_SCREEN_NAME_GENERATOR = "users.screen.name.generator";

	public static final String USERS_SCREEN_NAME_VALIDATOR = "users.screen.name.validator";

	public static final String USERS_SEARCH_WITH_INDEX = "users.search.with.index";

	public static final String USERS_UPDATE_LAST_LOGIN = "users.update.last.login";

	public static final String USERS_UPDATE_USER_NAME = "users.update.user.name.";

	public static final String VALUE_OBJECT_ENTITY_BLOCKING_CACHE = "value.object.entity.blocking.cache";

	public static final String VALUE_OBJECT_ENTITY_CACHE_ENABLED = "value.object.entity.cache.enabled";

	public static final String VALUE_OBJECT_ENTITY_THREAD_LOCAL_CACHE_MAX_SIZE = "value.object.entity.thread.local.cache.max.size";

	public static final String VALUE_OBJECT_FINDER_BLOCKING_CACHE = "value.object.finder.blocking.cache";

	public static final String VALUE_OBJECT_FINDER_CACHE_ENABLED = "value.object.finder.cache.enabled";

	public static final String VALUE_OBJECT_FINDER_THREAD_LOCAL_CACHE_MAX_SIZE = "value.object.finder.thread.local.cache.max.size";

	public static final String VALUE_OBJECT_LISTENER = "value.object.listener.";

	public static final String VELOCITY_ENGINE_LOGGER = "velocity.engine.logger";

	public static final String VELOCITY_ENGINE_LOGGER_CATEGORY = "velocity.engine.logger.category";

	public static final String VELOCITY_ENGINE_RESOURCE_LISTENERS = "velocity.engine.resource.listeners";

	public static final String VELOCITY_ENGINE_RESOURCE_MANAGER = "velocity.engine.resource.manager";

	public static final String VELOCITY_ENGINE_RESOURCE_MANAGER_CACHE = "velocity.engine.resource.manager.cache";

	public static final String VELOCITY_ENGINE_RESOURCE_MANAGER_CACHE_ENABLED = "velocity.engine.resource.manager.cache.enabled";

	public static final String VELOCITY_ENGINE_RESOURCE_MANAGER_MODIFICATION_CHECK_INTERVAL = "velocity.engine.resource.manager.modification.check.interval";

	public static final String VELOCITY_ENGINE_VELOCIMACRO_LIBRARY = "velocity.engine.velocimacro.library";

	public static final String VERIFY_FREQUENCY = "verify.frequency";

	public static final String VERIFY_PROCESSES = "verify.processes";

	public static final String VIRTUAL_HOSTS_DEFAULT_COMMUNITY_NAME = "virtual.hosts.default.community.name";

	public static final String VIRTUAL_HOSTS_IGNORE_EXTENSIONS = "virtual.hosts.ignore.extensions";

	public static final String VIRTUAL_HOSTS_IGNORE_HOSTS = "virtual.hosts.ignore.hosts";

	public static final String VIRTUAL_HOSTS_IGNORE_PATHS = "virtual.hosts.ignore.paths";

	public static final String WEB_SERVER_DISPLAY_NODE = "web.server.display.node";

	public static final String WEB_SERVER_HOST = "web.server.host";

	public static final String WEB_SERVER_HTTP_PORT = "web.server.http.port";

	public static final String WEB_SERVER_HTTPS_PORT = "web.server.https.port";

	public static final String WEB_SERVER_PROTOCOL = "web.server.protocol";

	public static final String WEBDAV_IGNORE = "webdav.ignore";

	public static final String WIDGET_SERVLET_MAPPING = "widget.servlet.mapping";

	public static final String WIKI_EMAIL_FROM_ADDRESS = "wiki.email.from.address";

	public static final String WIKI_EMAIL_FROM_NAME = "wiki.email.from.name";

	public static final String WIKI_EMAIL_PAGE_ADDED_BODY = "wiki.email.page.added.body";

	public static final String WIKI_EMAIL_PAGE_ADDED_ENABLED = "wiki.email.page.added.enabled";

	public static final String WIKI_EMAIL_PAGE_ADDED_SIGNATURE = "wiki.email.page.added.signature";

	public static final String WIKI_EMAIL_PAGE_ADDED_SUBJECT_PREFIX = "wiki.email.page.added.subject.prefix";

	public static final String WIKI_EMAIL_PAGE_UPDATED_BODY = "wiki.email.page.updated.body";

	public static final String WIKI_EMAIL_PAGE_UPDATED_ENABLED = "wiki.email.page.updated.enabled";

	public static final String WIKI_EMAIL_PAGE_UPDATED_SIGNATURE = "wiki.email.page.updated.signature";

	public static final String WIKI_EMAIL_PAGE_UPDATED_SUBJECT_PREFIX = "wiki.email.page.updated.subject.prefix";

	public static final String WIKI_FORMATS = "wiki.formats";

	public static final String WIKI_FORMATS_CONFIGURATION_INTERWIKI = "wiki.formats.configuration.interwiki";

	public static final String WIKI_FORMATS_CONFIGURATION_MAIN = "wiki.formats.configuration.main";

	public static final String WIKI_FORMATS_DEFAULT = "wiki.formats.default";

	public static final String WIKI_FORMATS_EDIT_PAGE = "wiki.formats.edit.page";

	public static final String WIKI_FORMATS_ENGINE = "wiki.formats.engine";

	public static final String WIKI_FORMATS_HELP_PAGE = "wiki.formats.help.page";

	public static final String WIKI_FORMATS_HELP_URL = "wiki.formats.help.url";

	public static final String WIKI_FRONT_PAGE_NAME = "wiki.front.page.name";

	public static final String WIKI_IMPORTERS = "wiki.importers";

	public static final String WIKI_IMPORTERS_CLASS = "wiki.importers.class";

	public static final String WIKI_IMPORTERS_PAGE = "wiki.importers.page";

	public static final String WIKI_INITIAL_NODE_NAME = "wiki.initial.node.name";

	public static final String WIKI_PAGE_COMMENTS_ENABLED  = "wiki.page.comments.enabled";

	public static final String WIKI_PAGE_RATINGS_ENABLED  = "wiki.page.ratings.enabled";

	public static final String WIKI_PAGE_TITLES_REGEXP = "wiki.page.titles.regexp";

	public static final String WIKI_PAGE_TITLES_REMOVE_REGEXP = "wiki.page.titles.remove.regexp";

	public static final String WIKI_RSS_ABSTRACT_LENGTH = "wiki.rss.abstract.length";

	public static final String YM_LOGIN = "ym.login";

	public static final String YM_PASSWORD = "ym.password";

}