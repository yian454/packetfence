--
-- category of temporary password is not mandatory
--

ALTER TABLE `temporary_password` MODIFY category int DEFAULT NULL;

--
-- Add a column to store the remaining available network access time of a node
--
ALTER TABLE node ADD `timeleft` int unsigned AFTER `lastskip`;