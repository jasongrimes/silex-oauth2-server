--
-- SQLite schema
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
  `redirect_uri` varchar(250) DEFAULT '',
  `owner_type` VARCHAR(5) NOT NULL DEFAULT 'user',
  `owner_id` varchar(255) DEFAULT '',
  `auth_code` varchar(40) DEFAULT '',
  `access_token` varchar(40) DEFAULT '',
  `refresh_token` varchar(40) DEFAULT '',
  `access_token_expires` int(10) DEFAULT NULL,
  `stage` VARCHAR(10) NOT NULL DEFAULT 'requested',
  `first_requested` unsigned int(10) NOT NULL,
  `last_updated` unsigned int(10) NOT NULL
);

CREATE TABLE `oauth_scopes` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `scope` varchar(255) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) DEFAULT '',
  UNIQUE (`scope`)
);

CREATE TABLE `oauth_session_scopes` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `session_id` unsigned int(11) NOT NULL,
  `scope_id` unsigned int(11) NOT NULL,
  CONSTRAINT `oauth_session_scopes_ibfk_5` FOREIGN KEY (`scope_id`) REFERENCES `oauth_scopes` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_session_scopes_ibfk_4` FOREIGN KEY (`session_id`) REFERENCES `oauth_sessions` (`id`) ON DELETE CASCADE
);
