-- Tables of the ed3k index node (docs/ed3k-index-node.md).
--
-- Applied by MySQLEngine.InitEd3k, only when ed3k is enabled, one statement at a
-- time. Every statement is idempotent (IF NOT EXISTS), so this runs on every start.
-- Times are Unix milliseconds unless a column is a datetime. Byte strings that are
-- compared (words, ext) use a binary collation: ed3k matches words byte for byte.

-- One row per (kind, target) that holds or held records: the row a store locks,
-- the file count of a keyword target and the time it last answered FULL.
CREATE TABLE IF NOT EXISTS `ed3k_targets` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `kind` tinyint(3) unsigned NOT NULL,
  `target` binary(16) NOT NULL,
  `files` int(10) unsigned NOT NULL DEFAULT '0',
  `full_at` bigint(20) NOT NULL DEFAULT '0',
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `kind_target` (`kind`,`target`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `ed3k_sources` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `target` binary(16) NOT NULL,
  `node_id` binary(16) NOT NULL,
  -- The serialised Peer as it is answered.
  `peer` varbinary(2048) NOT NULL,
  `host` varchar(64) NOT NULL,
  `site` varchar(64) NOT NULL,
  -- Observed IPv4 endpoint of a direct IPv4 connection (6 bytes), for the eD2K bridge.
  `ep4` varbinary(6) DEFAULT NULL,
  `ed2k_cap` tinyint(1) NOT NULL DEFAULT '0',
  `lifetime_end` bigint(20) NOT NULL,
  -- When the row goes: lifetime_end, or later while kept_by's connection is open.
  `expires` bigint(20) NOT NULL,
  `kept_by` varchar(96) DEFAULT NULL,
  `page_key` binary(32) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_node` (`target`,`node_id`),
  KEY `target_page` (`target`,`page_key`),
  KEY `target_host` (`target`,`host`),
  KEY `target_site` (`target`,`site`),
  KEY `expires` (`expires`),
  KEY `host` (`host`),
  KEY `site` (`site`),
  KEY `kept_by` (`kept_by`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `ed3k_keywords` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `target` binary(16) NOT NULL,
  `root` binary(32) NOT NULL,
  -- root[0..16): the file target, for the eD2K bridge join with ed3k_sources.
  `root_target` binary(16) NOT NULL,
  `pubkey` binary(32) NOT NULL,
  `publisher_id` binary(16) NOT NULL,
  `signed` varbinary(1100) NOT NULL,
  `signed_hash` binary(32) NOT NULL,
  -- The words of the name, each followed by 0x1F and the list led by one.
  `words` text NOT NULL,
  `ext` varchar(64) NOT NULL DEFAULT '',
  `size` bigint(20) unsigned NOT NULL DEFAULT '0',
  `sources` int(10) unsigned NOT NULL DEFAULT '0',
  `ed2k` binary(16) DEFAULT NULL,
  `host` varchar(64) NOT NULL,
  `site` varchar(64) NOT NULL,
  `via_signer` tinyint(1) NOT NULL DEFAULT '0',
  `stored_at` bigint(20) NOT NULL,
  `expires` bigint(20) NOT NULL,
  `page_key` binary(32) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_root_key` (`target`,`root`,`pubkey`),
  KEY `target_page` (`target`,`page_key`),
  KEY `target_key` (`target`,`pubkey`),
  KEY `target_site_root` (`target`,`site`,`root`),
  KEY `expires` (`expires`),
  KEY `host` (`host`),
  KEY `site` (`site`),
  KEY `ed2k` (`ed2k`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS `ed3k_notes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `target` binary(16) NOT NULL,
  `pubkey` binary(32) NOT NULL,
  `signed` varbinary(1100) NOT NULL,
  `signed_hash` binary(32) NOT NULL,
  `host` varchar(64) NOT NULL,
  `site` varchar(64) NOT NULL,
  `expires` bigint(20) NOT NULL,
  `page_key` binary(32) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `target_key` (`target`,`pubkey`),
  KEY `target_page` (`target`,`page_key`),
  KEY `target_host` (`target`,`host`),
  KEY `target_site` (`target`,`site`),
  KEY `expires` (`expires`),
  KEY `host` (`host`),
  KEY `site` (`site`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- The paging secret (§10.3), shared by every instance on this database.
CREATE TABLE IF NOT EXISTS `ed3k_state` (
  `id` bigint(20) unsigned NOT NULL,
  `secret` binary(32) NOT NULL,
  `rotated_at` bigint(20) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
