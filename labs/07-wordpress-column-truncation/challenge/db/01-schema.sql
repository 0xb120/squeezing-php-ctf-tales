-- "wp-like" schema. The interesting part is the charset and the length of
-- usermeta.meta_value.
CREATE TABLE users (
  id    INT AUTO_INCREMENT PRIMARY KEY,
  login VARCHAR(60) NOT NULL
) DEFAULT CHARSET = utf8;

CREATE TABLE usermeta (
  umeta_id   INT AUTO_INCREMENT PRIMARY KEY,
  user_id    INT          NOT NULL,
  -- Legacy columns: still on MySQL's 3-byte "utf8" (utf8mb3), and still sized
  -- for the 2011 version of the profile editor.
  meta_key   VARCHAR(64)  CHARACTER SET utf8 NOT NULL,
  meta_value VARCHAR(255) CHARACTER SET utf8 NULL,
  UNIQUE KEY user_key (user_id, meta_key)
) DEFAULT CHARSET = utf8;
