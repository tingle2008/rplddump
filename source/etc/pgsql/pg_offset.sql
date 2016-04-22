drop table pg_offset;

create table pg_offset (
    filename text unique,
    filemtime text,
    fileoff text
);
grant select, update, insert on pg_offset to pguser;
insert into pg_offset values('pg_lastupdate', 0, 0);
insert into pg_offset values('log', 12345, 0);
