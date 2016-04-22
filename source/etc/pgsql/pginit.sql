DROP TABLE log;
DROP TABLE pg_offset;
DROP DATABASE db_pgtest;
DROP USER pguser;

CREATE USER pguser PASSWORD '123';
CREATE DATABASE db_pgtest OWNER pguser;
