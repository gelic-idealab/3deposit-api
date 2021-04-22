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

CREATE TABLE `deposit_types` (
    `id` int NOT NULL AUTO_INCREMENT,
    `type` varchar(20) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE `deposits` (
    `id` varchar(50) NOT NULL,
    `name` varchar(50) NOT NULL,
    `desc` varchar(250) NOT NULL,
    `created` timestamp,
    `updated` timestamp NOT NULL,
    `type_id` int NOT NULL,
    `size` bigint NOT NULL,
    `upload_by` int NOT NULL,
    UNIQUE (id),
    PRIMARY KEY (id),
    FOREIGN KEY (type_id) REFERENCES deposit_types(id),
    FOREIGN KEY (upload_by) REFERENCES users(id)
);

CREATE TABLE 'organizations' (
    `id` varchar NOT NULL,
    `name` varchar NOT NULL,
    `desc` text NOT NULL
);

CREATE TABLE 'collections' (
    `id` varchar NOT NULL,
    `name` varchar NOT NULL,
    `desc` text NOT NULL,
    `org_id` varchar DEFAULT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (org_id) REFERENCES organizations(id),
);

CREATE TABLE 'items' (
    `id` varchar NOT NULL,
    `name` varchar NOT NULL,
    `desc` text NOT NULL,
    `collection_id` varchar DEFAULT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (collection_id) REFERENCES collections(id),
);

CREATE TABLE 'entities' (
    `id` varchar NOT NULL,
    `name` varchar NOT NULL,
    `desc` text NOT NULL,
    `item_id` varchar DEFAULT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (item_id) REFERENCES items(id),
);

CREATE TABLE 'files' (
    `id` varchar NOT NULL,
    `name` varchar NOT NULL,
    `desc` text NOT NULL,
    `entity_id` varchar DEFAULT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (entity_id) REFERENCES entities(id),
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
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (deposit_id) REFERENCES deposits(id)
);

CREATE TABLE `metadata_fields` (
    `id` int NOT NULL AUTO_INCREMENT,
    `label` varchar(256) NOT NULL,
    `schema` varchar(64) NOT NULL,
    `tag` varchar(128) NOT NULL,
    `note` varchar (4096),
    `required` tinyint NOT NULL,
    `scope` varchar(45),
    `media_type` varchar(45),
    PRIMARY KEY (id)
);

CREATE TABLE `metadata_values` (
    `id` int NOT NULL AUTO_INCREMENT,
    `deposit_id` varchar(50) NOT NULL,
    `file_id` varchar(50),
    `metadata_id` int NOT NULL,
    `value` varchar(4096),
    `updated` timestamp NOT NULL,
    `updated_by` int NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (metadata_id) REFERENCES metadata_fields(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE `metadata_vocab` (
    `id` int NOT NULL AUTO_INCREMENT,
    `field_id` int NOT NULL,
    `vocab_item` varchar(256),
    PRIMARY KEY (id),
    FOREIGN KEY (field_id) REFERENCES metadata_fields(id)
);