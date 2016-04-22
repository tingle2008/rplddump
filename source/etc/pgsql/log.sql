drop table log;

create table log (
    time text,
    ps text,
    cmd  text,
    input text,
    fname text
);

grant select, update, insert on log to pguser;

