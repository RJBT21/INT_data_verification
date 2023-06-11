CREATE DATABASE IF NOT EXISTS int_verification  DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;
USE int_verification;
CREATE TABLE IF NOT EXISTS `switch_info`(
    `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'ID',
    `switch_id` varchar(255) NOT NULL,
    `secret_key` varchar(255) NOT NULL,
    `echo_timestamp` varchar(255) NOT NULL COMMENT "the time of switch initination",
    `valid_interval` int(11) NOT NULL COMMENT "interval of totp_code regeneration",
    `totp_code_length` int(11) NOT NULL,
    PRIMARY KEY  (`id`),
    UNIQUE KEY `uni_switch_id` (`switch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=UTF8; 