-- ─────────────────────────────────────────────────────────────
--  CyberDrishti — Entity Type Enum Migration
--  Run this ONCE against the live database to add new entity
--  types introduced in Phase 1.
--
--  Safe to run multiple times — IF NOT EXISTS style via DO block.
--  PostgreSQL does not support IF NOT EXISTS on ALTER TYPE ADD VALUE
--  directly, but we guard with a DO block check.
-- ─────────────────────────────────────────────────────────────

DO $$
DECLARE
    existing_values TEXT[];
    v TEXT;
    new_values TEXT[] := ARRAY[
        'ABHA_ID', 'AWS_CONFIG', 'AWS_CREDS', 'AWS_KEY', 'AZURE_CREDS',
        'CI_CONFIG', 'CLOUD_METADATA', 'KUBE_CONFIG', 'MEMORY_DUMP',
        'SECRET_FIELD', 'SESSION_DATA', 'SHELL_HISTORY', 'SOURCE_CODE',
        'SPRING_BOOT', 'STRIPE_KEY', 'UPI_ID'
    ];
BEGIN
    -- Get current enum values
    SELECT array_agg(enumlabel::TEXT)
    INTO existing_values
    FROM pg_enum e
    JOIN pg_type t ON e.enumtypid = t.oid
    WHERE t.typname = 'entity_type';

    -- Add each missing value
    FOREACH v IN ARRAY new_values LOOP
        IF NOT (v = ANY(existing_values)) THEN
            EXECUTE format('ALTER TYPE entity_type ADD VALUE %L', v);
            RAISE NOTICE 'Added entity_type value: %', v;
        ELSE
            RAISE NOTICE 'Already exists, skipping: %', v;
        END IF;
    END LOOP;
END $$;

-- Verify
SELECT enumlabel AS entity_type_value
FROM pg_enum e
JOIN pg_type t ON e.enumtypid = t.oid
WHERE t.typname = 'entity_type'
ORDER BY enumlabel;
