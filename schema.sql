CREATE TABLE user (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  profile_pic TEXT NOT NULL
);

CREATE TABLE certs (
 serial_number PRIMARY KEY NUMERIC NOT NULL,
 cert TEXT NOT NULL,
 sec_key TEXT NOT NULL,
 is_crl INTEGER
);