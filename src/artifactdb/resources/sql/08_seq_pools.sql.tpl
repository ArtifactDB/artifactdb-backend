 CREATE TABLE {schema_name}.seq_pools (
    pool_id serial PRIMARY KEY,
	pool_type varchar NOT NULL,
	pool_status varchar NOT NULL,
	lower_limit integer NOT NULL,
	upper_limit integer,
	created_at timestamp with TIME ZONE DEFAULT (now() at time zone 'utc')
);
