-- Tunnels with max_connections = 0 could be created before the server started
-- validating the field (an empty admin form input became Number("") = 0). A 0
-- value makes the "active >= max_connections" check always true, silently
-- rejecting every connection while the tunnel still shows as ready. Backfill
-- existing rows to the schema default (100).
UPDATE tunnels SET max_connections = 100 WHERE max_connections < 1;
