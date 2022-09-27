CREATE OR REPLACE FUNCTION {schema_name}.next_seq()
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
    declare v_lower_limit int4;
   			v_curr_seq int4;
   			v_is_restricted int4;
   			v_is_provisioned int4;
     		seq_val int4;
    BEGIN
    
    select lower_limit from {schema_name}.seq_pools where pool_status = 'ACTIVE' and pool_type = 'PROVISIONED' into v_lower_limit;
    
    if v_lower_limit is null then
        raise exception 'No active provisioned pool' using hint = 'Please create provisioned pool';
    end if;
    
    v_curr_seq = {schema_name}.curr_seq(); 
    
    if v_curr_seq is null then
        seq_val = v_lower_limit;
    else
        seq_val = v_curr_seq+1;
    end if;

    -- at this point, seq_val needs to match a provisioned pool, but it can also be
    -- outside of the pool. Ex: provision(20,30) then provision(40,50).
    -- seq_val = 31, passed the first pool, but not yet in the next one. We need to
    if seq_val < v_lower_limit then
        seq_val = v_lower_limit;
    end if;

    
    -- are we within an existing restricted pool ?
    select count(*) from {schema_name}.seq_pools where pool_status = 'ACTIVE' and pool_type = 'RESTRICTED' and seq_val>=lower_limit and seq_val<=upper_limit into v_is_restricted;
    
    if v_is_restricted > 0 then 
        -- if within a restricted pool, increment to the upper limit + 1 of the poll
        -- (we pass the pool limits)
        select min(s_p.upper_limit+1) 
            from {schema_name}.seq_pools s_p 
            where   s_p.pool_status = 'ACTIVE'
                and s_p.pool_type = 'RESTRICTED'
                and s_p.upper_limit+1>seq_val
                and not exists (
                    select 1
                        from {schema_name}.seq_pools s_p2 
                        where   s_p2.pool_status = 'ACTIVE' 
                            and s_p2.pool_type = 'RESTRICTED'
                            and s_p.upper_limit+1>=s_p2.lower_limit
                            and s_p.upper_limit+1<=s_p2.upper_limit
                ) into seq_val;
    end if;

    
    select count(*)
        from  {schema_name}.seq_pools
        where   pool_status = 'ACTIVE' 
            and pool_type = 'PROVISIONED'
            and seq_val>=lower_limit
            and seq_val<=upper_limit
        into v_is_provisioned;
    
    if v_is_provisioned = 0 then
        raise exception 'Unable to create valid object seq number' using hint = 'Please verify defined pools (table: seq_pools)';
    end if;
    
    insert into {schema_name}.artifact_versions (artifact_seq, curr_version_num) values (seq_val, 0);
    
    return seq_val;

    END;
$function$
;
