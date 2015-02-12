---
--- PacketFence SQL schema upgrade from X.X.X to X.Y.Z
---

--
-- Insert a new 'default' user
--

INSERT INTO `person` (pid,notes) VALUES ("default","Default User - do not delete");
INSERT INTO temporary_password (pid, password, valid_from, expiration, access_duration, access_level, category) VALUES ('default', 'default', NOW(), '2038-01-01', NULL, 'NONE', NULL);
