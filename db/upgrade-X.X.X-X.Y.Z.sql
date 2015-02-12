---
--- PacketFence SQL schema upgrade from X.X.X to X.Y.Z
---

--
-- Insert a new 'default' user
--

INSERT INTO `person` (pid,notes) VALUES ("default","Default User - do not delete");
