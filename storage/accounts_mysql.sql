-- Account tables for the client-facing Meta API (docs/meta-api.md).
--
-- Applied by MySQLEngine.InitAccounts, only when metaApi.accounts is enabled, one
-- statement at a time. Every statement is idempotent (IF NOT EXISTS), so this runs on
-- every start and also brings an existing eD2K database up to date — unlike
-- misc/enode.sql, which only ever runs against an empty database.
--
-- Nothing here is specific to a registration step or a payment provider: a step
-- keeps its own state in account_steps.data, and every provider's orders live in
-- payments, told apart by `provider`.

CREATE TABLE IF NOT EXISTS `accounts` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  -- Normalized to lower case by the application before every insert and lookup.
  `username` varchar(64) NOT NULL,
  `email` varchar(254) NOT NULL DEFAULT '',
  `password_hash` varchar(255) NOT NULL,
  -- enode.meta.v1.AccountState: 1 pending, 2 active, 3 expired, 4 disabled.
  `state` tinyint(3) unsigned NOT NULL DEFAULT '1',
  -- End of the paid-for period; NULL means access does not expire.
  `access_until` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  KEY `state` (`state`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `account_steps` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `account_id` bigint(20) unsigned NOT NULL,
  -- The step's id from metaApi.accounts.steps, e.g. "payment".
  `step_id` varchar(32) NOT NULL,
  -- 0 pending, 1 done, 2 failed, 3 skipped.
  `status` tinyint(3) unsigned NOT NULL DEFAULT '0',
  -- The step's own state, JSON by convention, opaque to the server core.
  `data` blob,
  `completed_at` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `account_step` (`account_id`,`step_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `payments` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `account_id` bigint(20) unsigned NOT NULL,
  `step_id` varchar(32) NOT NULL,
  `plan_id` varchar(64) NOT NULL DEFAULT '',
  -- The payment backend, e.g. "woocommerce".
  `provider` varchar(32) NOT NULL,
  -- The provider's order or invoice id; NULL until the checkout exists, so the
  -- unique key below does not collide on the not-yet-created rows.
  `external_id` varchar(128) DEFAULT NULL,
  `external_key` varchar(255) NOT NULL DEFAULT '',
  -- 0 created, 1 pending, 2 paid, 3 failed, 4 cancelled, 5 refunded.
  `status` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `amount` varchar(32) NOT NULL DEFAULT '',
  `currency` varchar(8) NOT NULL DEFAULT '',
  `period_days` int(10) unsigned NOT NULL DEFAULT '0',
  -- Set exactly once, when the payment's access was granted.
  `credited_at` datetime(6) DEFAULT NULL,
  -- Set exactly once, when a credited payment was refunded or cancelled and its
  -- access taken back.
  `revoked_at` datetime(6) DEFAULT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `provider_external` (`provider`,`external_id`),
  KEY `account_id` (`account_id`),
  KEY `status` (`status`),
  KEY `credited_at` (`credited_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `account_sessions` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `account_id` bigint(20) unsigned NOT NULL,
  -- SHA-256 of the token; the token itself is never stored.
  `token_hash` binary(32) NOT NULL,
  `client` varchar(64) NOT NULL DEFAULT '',
  `expires_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL,
  `updated_at` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token_hash` (`token_hash`),
  KEY `account_id` (`account_id`),
  KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
