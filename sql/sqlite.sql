--
-- SQLite-flavored DDL for setting up database schema.
--

CREATE TABLE `oauth_clients` (
  `id` varchar(40) NOT NULL DEFAULT '',
  `secret` varchar(40) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `auto_approve` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
);

CREATE TABLE `oauth_client_endpoints` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `redirect_uri` varchar(255) DEFAULT NULL,
  CONSTRAINT `oauth_client_endpoints_ibfk_1` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE `oauth_sessions` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `owner_type` VARCHAR(6) NOT NULL DEFAULT 'user',
  `owner_id` varchar(255) DEFAULT ''
);

CREATE TABLE `oauth_session_access_tokens` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `session_id` unsigned int(10) NOT NULL,
  `access_token` varchar(40) DEFAULT '',
  `access_token_expires` int(10) DEFAULT NULL
);

CREATE TABLE `oauth_session_authcodes` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `session_id` unsigned int(10) NOT NULL,
  `auth_code` varchar(40) DEFAULT '',
  `auth_code_expires` int(10) DEFAULT NULL
);

CREATE TABLE `oauth_session_redirects` (
  `session_id` unsigned int(10) PRIMARY KEY NOT NULL,
  `redirect_uri` varchar(255) NOT NULL
);

CREATE TABLE `oauth_session_refresh_tokens` (
  `session_access_token_id` INTEGER PRIMARY KEY NOT NULL,
  `refresh_token` char(40) NOT NULL,
  `refresh_token_expires` unsigned int(10) NOT NULL,
  `client_id` varchar(40) NOT NULL
);

CREATE TABLE `oauth_scopes` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `scope` varchar(255) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) DEFAULT '',
  UNIQUE (`scope`)
);

CREATE TABLE `oauth_session_token_scopes` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `session_access_token_id` unsigned int(11) NOT NULL,
  `scope_id` unsigned int(5) NOT NULL
);

CREATE TABLE `oauth_session_authcode_scopes` (
  `oauth_session_authcode_id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `scope_id` unsigned int(5) NOT NULL
);
