USE `3deposit`;

CREATE TABLE `roles` (
    `id`  tinyint NOT NULL AUTO_INCREMENT,
    `role_name` varchar(20),
    PRIMARY KEY (id)
);

CREATE TABLE `users` (
    `id`  int NOT NULL AUTO_INCREMENT,
    `email` varchar(50) NOT NULL,
    `password`  varchar(50) NOT NULL,
    `first_name` varchar(20) NOT NULL,
    `last_name` varchar(20) NOT NULL,
    `role_id`  tinyint NOT NULL,
    `last_login_at` timestamp,
    UNIQUE (id, email),
    PRIMARY KEY (id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE `members` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `user_id` INT NULL,
  `ref_id` INT NULL,
  `scope` varchar(20) NULL,
  `role` varchar(20) NULL,
  PRIMARY KEY (`id`));


CREATE TABLE `deposit_types` (
    `id` int NOT NULL AUTO_INCREMENT,
    `type` varchar(20) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `organizations` (
    `id` int NOT NULL AUTO_INCREMENT,
    `name` varchar(256) NOT NULL,
    `desc` varchar(4096) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `collections` (
    `id` int NOT NULL AUTO_INCREMENT,
    `name` varchar(256) NOT NULL,
    `desc` varchar(4096) NOT NULL,
    `org_id` int DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `items` (
    `id` int NOT NULL AUTO_INCREMENT,
    `name` varchar(256) NOT NULL,
    `desc` varchar(4096) NOT NULL,
    `collection_id` int DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `entities` (
    `id` int NOT NULL AUTO_INCREMENT,
    `name` varchar(256),
    `desc` varchar(4096) NOT NULL,
    `item_id` int DEFAULT NULL
)

CREATE TABLE `files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(256) NOT NULL,
  `desc` varchar(4096) NOT NULL,
  `entity_id` int(11) DEFAULT NULL,
  `filename` varchar(45) DEFAULT NULL,
  `md5` varchar(45) DEFAULT NULL,
  `size` int(11) DEFAULT NULL,
  `ext` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `tokens` (
    `id` int NOT NULL AUTO_INCREMENT,
    `token` varchar(128) NOT NULL,
    `user_id` int NOT NULL,
    `expires` timestamp,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE `events` (
    `id` int NOT NULL AUTO_INCREMENT,
    `user_id` int NOT NULL,
    `deposit_id` varchar(50) NOT NULL,
    `event_scope` varchar(50) NOT NULL,
    `event_target` int NOT NULL,
    `event_type` varchar(128) NOT NULL,
    `event_timestamp` timestamp NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_fields` (
    `id` int NOT NULL AUTO_INCREMENT,
    `label` varchar(256) NOT NULL,
    `schema` varchar(64) NOT NULL,
    `tag` varchar(128) NOT NULL,
    `note` varchar (4096),
    `required` tinyint NOT NULL,
    `org_id` int DEFAULT NULL,
    `collection_id` int DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_values` (
    `id` int NOT NULL AUTO_INCREMENT,
    `file_id` varchar(50),
    `metadata_id` int NOT NULL,
    `value` varchar(4096),
    `updated` timestamp,
    `updated_by` int,
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_vocab` (
    `id` int NOT NULL AUTO_INCREMENT,
    `field_id` int NOT NULL,
    `vocab_item` varchar(256),
    PRIMARY KEY (id)
);