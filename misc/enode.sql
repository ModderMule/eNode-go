-- phpMyAdmin SQL Dump
-- version 3.3.8
-- http://www.phpmyadmin.net
--
-- Servidor: localhost
-- Tiempo de generación: 09-02-2013 a las 13:28:42
-- Versión del servidor: 5.5.29
-- Versión de PHP: 5.4.6-1ubuntu1.1

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Base de datos: `enode`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `clients`
--

CREATE TABLE IF NOT EXISTS `clients` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `hash` binary(16) NOT NULL DEFAULT '0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
  `id_ed2k` int(10) unsigned NOT NULL DEFAULT '0',
  `ipv4` int(10) unsigned NOT NULL DEFAULT '0',
  `port` smallint(5) unsigned NOT NULL DEFAULT '0',
  -- eMule OP_FOUNDSOURCES_OBFU crypt options for this client: bit 0x01 supports,
  -- 0x02 requests, 0x04 requires obfuscation. Parsed from the CT_SERVER_FLAGS
  -- login tag and re-published per source.
  `crypt_options` tinyint(1) unsigned NOT NULL DEFAULT '0',
  -- Client's public IPv6 as 16 raw network-order bytes, NULL when the client has
  -- none. ipv6_reachable is set once the server has verified the client answers
  -- on that address; only a reachable IPv6 is published as a source.
  `ipv6` binary(16) DEFAULT NULL,
  `ipv6_reachable` tinyint(1) NOT NULL DEFAULT '0',
  `time_login` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `online` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `hash` (`hash`),
  KEY `id_ed2k` (`id_ed2k`),
  -- Composite rather than a bare (online): `online` leads, so COUNT(*) WHERE
  -- online = 1 still gets its range scan, and the stale-row sweep's
  -- `online = 0 AND time_login < ?` is covered too instead of filtering row by
  -- row over every client ever seen.
  KEY `online_time_login` (`online`,`time_login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `files`
--

CREATE TABLE IF NOT EXISTS `files` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `hash` binary(16) NOT NULL DEFAULT '0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
  `size` bigint(20) NOT NULL DEFAULT '0',
  `time_creation` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `time_offer` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `source_id` int(10) unsigned NOT NULL DEFAULT '0',
  `source_port` smallint(5) unsigned NOT NULL DEFAULT '0',
  `sources` int(11) NOT NULL DEFAULT '0',
  `completed` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  -- `hash` leads, so this also serves the hash-only lookups (the offer's id
  -- lookup, OP_GLOBGETSOURCES, shared-now); a separate KEY hash only cost writes.
  UNIQUE KEY `hash_size` (`hash`,`size`),
  KEY `size` (`size`),
  KEY `time_creation` (`time_creation`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `sources`
--

CREATE TABLE IF NOT EXISTS `sources` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `id_file` bigint(20) unsigned NOT NULL DEFAULT '0',
  `id_client` bigint(20) unsigned NOT NULL DEFAULT '0',
  `name` varchar(255) NOT NULL DEFAULT '',
  `ext` varchar(8) NOT NULL DEFAULT '',
  `time_offer` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `type` enum('Image','Audio','Video','Pro','Doc','') NOT NULL DEFAULT '',
  `rating` tinyint(2) unsigned NOT NULL DEFAULT '0',
  `title` varchar(128) NOT NULL DEFAULT '',
  `artist` varchar(128) NOT NULL DEFAULT '',
  `album` varchar(128) NOT NULL DEFAULT '',
  `length` int(8) unsigned NOT NULL DEFAULT '0',
  `bitrate` int(8) unsigned NOT NULL DEFAULT '0',
  `codec` varchar(32) NOT NULL DEFAULT '',
  `online` tinyint(1) NOT NULL DEFAULT '0',
  `complete` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  -- `id_file` leads, so this also serves every per-file lookup, the counter
  -- refresh and the sources_ibfk_1 foreign key; no separate KEY id_file.
  UNIQUE KEY `id_file+id_client` (`id_file`,`id_client`),
  KEY `id_client` (`id_client`),
  KEY `time_offer` (`time_offer`),
  -- Composite rather than a bare (online): `online` leads, so the startup reset's
  -- `WHERE online = 1` still gets its range scan, and the sweep's
  -- `online = 0 AND time_offer < ?` is covered too.
  KEY `online_time_offer` (`online`,`time_offer`),
  KEY `complete` (`complete`),
  KEY `ext` (`ext`),
  KEY `type` (`type`),
  -- Full-text index backing name search, so OP_SEARCHREQUEST uses an index
  -- instead of a leading-wildcard `LIKE '%term%'` table scan. This baseline is
  -- the plain word parser, portable to MariaDB 10.0.5+ and MySQL 5.6.4+, and it
  -- gives word-prefix matching (dialect: mariadb). On MySQL the engine
  -- specializes it to `WITH PARSER ngram` for substring matching on first connect
  -- (dialect: mysql, MySQL 5.7.6+); see specializeFulltextIndex. Keeping the index
  -- here means a manually-applied schema still answers MATCH on either server.
  FULLTEXT KEY `name_ft` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Filtros para las tablas descargadas (dump)
--

--
-- Filtros para la tabla `sources`
--
ALTER TABLE `sources`
  ADD CONSTRAINT `sources_ibfk_1` FOREIGN KEY (`id_file`) REFERENCES `files` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `sources_ibfk_2` FOREIGN KEY (`id_client`) REFERENCES `clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
