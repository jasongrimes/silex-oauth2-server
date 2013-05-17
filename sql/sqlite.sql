--
-- SQLite flavored DDL for OAuth2 server tables
--

CREATE TABLE `oauth2_clients` (
  `id` varchar(40) NOT NULL DEFAULT '',
  `secret` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `oauth2_client_redirect_uris` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `redirect_uri` varchar(255) NOT NULL DEFAULT '',
  KEY `client_id`,
  CONSTRAINT `oauth2_clients_fk_1` FOREIGN KEY (`client_id`) REFERENCES `oauth2_clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE `oauth2_auth_codes` (
  `code` varchar(40) NOT NULL DEFAULT '',
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `user_id` varchar(20) NOT NULL DEFAULT '',
  `redirect_uri` varchar(255) NOT NULL DEFAULT '',
  `expires` int(11) NOT NULL DEFAULT 0,
  `scope` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`code`)
);

CREATE TABLE `oauth2_access_tokens` (
  `oauth_token` varchar(40) NOT NULL,
  `client_id` varchar(40) NOT NULL,
  `user_id` int(11) NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`oauth_token`)
);

CREATE TABLE `oauth2_refresh_tokens` (
  `oauth_token` varchar(40) NOT NULL,
  `refresh_token` varchar(40) NOT NULL,
  `client_id` varchar(40) NOT NULL,
  `user_id` int(11) NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`oauth_token`)
);
