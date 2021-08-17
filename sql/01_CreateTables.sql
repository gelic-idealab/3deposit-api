USE `3deposit`;

CREATE TABLE `roles` (
    `id`  tinyint AUTO_INCREMENT,
    `role_name` varchar(20),
    PRIMARY KEY (id)
);

CREATE TABLE `users` (
    `id`  int AUTO_INCREMENT,
    `email` varchar(50),
    `password`  varchar(50),
    `first_name` varchar(20),
    `last_name` varchar(20),
    `role_id`  tinyint,
    `last_login_at` timestamp,
    UNIQUE (id, email),
    PRIMARY KEY (id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE `members` (
  `id` INT AUTO_INCREMENT,
  `user_id` INT NULL,
  `ref_id` INT NULL,
  `scope` varchar(20) NULL,
  `role` varchar(20) NULL,
  PRIMARY KEY (`id`));


CREATE TABLE `deposit_types` (
    `id` int AUTO_INCREMENT,
    `type` varchar(20),
    PRIMARY KEY (id)
);

CREATE TABLE `organizations` (
    `id` int AUTO_INCREMENT,
    `name` varchar(256),
    `desc` varchar(4096),
    PRIMARY KEY (id)
);

CREATE TABLE `collections` (
    `id` int AUTO_INCREMENT,
    `name` varchar(256),
    `desc` varchar(4096),
    `org_id` int DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `items` (
    `id` int AUTO_INCREMENT,
    `name` varchar(256),
    `desc` varchar(4096),
    `collection_id` int DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `entities` (
    `id` int AUTO_INCREMENT,
    `name` varchar(256),
    `desc` varchar(4096),
    `item_id` int DEFAULT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE `files` (
  `id` int(11) AUTO_INCREMENT,
  `name` varchar(256),
  `desc` varchar(4096),
  `entity_id` int(11) DEFAULT NULL,
  `filename` varchar(45) DEFAULT NULL,
  `md5` varchar(45) DEFAULT NULL,
  `size` int(11) DEFAULT NULL,
  `ext` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

CREATE TABLE `tokens` (
    `id` int AUTO_INCREMENT,
    `token` varchar(128),
    `user_id` int,
    `expires` timestamp,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE `events` (
    `id` int AUTO_INCREMENT,
    `user_id` int,
    `deposit_id` varchar(50),
    `event_scope` varchar(50),
    `event_target` int,
    `event_type` varchar(128),
    `event_timestamp` timestamp,
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_fields` (
    `id` int AUTO_INCREMENT,
    `label` varchar(256),
    `schema` varchar(64),
    `tag` varchar(128),
    `scope` varchar(128),
    `note` varchar (4096),
    `required` tinyint,
    `org_id` int DEFAULT NULL,
    `collection_id` int DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_values` (
    `id` int AUTO_INCREMENT,
    `file_id` varchar(50),
    `metadata_id` int,
    `value` varchar(4096),
    `updated` timestamp,
    `updated_by` int,
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_vocab` (
    `id` int AUTO_INCREMENT,
    `field_id` int,
    `vocab_item` varchar(256),
    PRIMARY KEY (id)
);