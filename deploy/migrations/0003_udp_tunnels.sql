-- Allow the new 'udp' kind and let TCP/UDP share a public port number. Drop
-- constraints by column rather than by name so the migration is robust across
-- databases where the auto-generated constraint names differ.
DO $$
DECLARE
    tunnel_row RECORD;
BEGIN
    FOR tunnel_row IN
        SELECT conname, contype
        FROM pg_constraint
        WHERE conrelid = 'tunnels'::regclass
          AND (
            contype = 'c' AND conkey = ARRAY[
                (SELECT attnum FROM pg_attribute
                 WHERE attrelid = 'tunnels'::regclass AND attname = 'kind')]::smallint[]
            OR contype = 'u' AND conkey = ARRAY[
                (SELECT attnum FROM pg_attribute
                 WHERE attrelid = 'tunnels'::regclass AND attname = 'public_port')]::smallint[]
          )
    LOOP
        EXECUTE format('ALTER TABLE tunnels DROP CONSTRAINT %I', tunnel_row.conname);
    END LOOP;
END $$;

ALTER TABLE tunnels ADD CONSTRAINT tunnels_kind_check CHECK(kind IN ('tcp', 'http', 'udp'));
ALTER TABLE tunnels ADD CONSTRAINT tunnels_kind_public_port_key UNIQUE(kind, public_port);
