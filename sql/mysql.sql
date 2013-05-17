--
-- MySQL flavored DDL for OAuth2 server tables
--

CREATE TABLE `oauth2_clients` (
  `id` varchar(40) NOT NULL DEFAULT '',
  `secret` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth2_client_redirect_uris` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `redirect_uri` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `client_id` (`client_id`),
  CONSTRAINT `oauth2_clients_fk_1` FOREIGN KEY (`client_id`) REFERENCES `oauth2_clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth2_auth_codes` (
  `code` varchar(40) NOT NULL DEFAULT '',
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `user_id` varchar(20) NOT NULL DEFAULT '',
  `redirect_uri` varchar(255) NOT NULL DEFAULT '',
  `expires` int(11) NOT NULL DEFAULT 0,
  `scope` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth2_access_tokens` (
  `oauth_token` varchar(40) NOT NULL,
  `client_id` varchar(40) NOT NULL,
  `user_id` int(11) UNSIGNED NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`oauth_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth2_refresh_tokens` (
  `oauth_token` varchar(40) NOT NULL,
  `refresh_token` varchar(40) NOT NULL,
  `client_id` varchar(40) NOT NULL,
  `user_id` int(11) UNSIGNED NOT NULL,
  `expires` int(11) NOT NULL,
  `scope` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`oauth_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
