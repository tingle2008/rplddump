#!/bin/bash

PSQL=`which psql 2>/dev/null`

[[ X$PSQL == X ]] && (echo 'no psql in PATH'; exit 1)

$PSQL -U postgres -f pginit.sql
$PSQL -U postgres -d db_pgtest -f log.sql
$PSQL -U postgres -d db_pgtest -f pg_offset.sql
