CREATE OR REPLACE FUNCTION {schema_name}.restrict_pool(p_lower_limit int4, p_upper_limit int4)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
    declare restricted_values int4;
    begin
        
	    if p_lower_limit >= p_upper_limit then
            raise exception 'Upper pool seq limit should be greater than lower limit' using hint = 'Please modify parameters';
        end if;
       
        lock table {schema_name}.seq_pools in access exclusive mode;

        select count(*) from {schema_name}.artifact_versions where artifact_seq >= p_lower_limit and artifact_seq <= p_upper_limit into restricted_values;
       
        if restricted_values > 0 then
            raise exception 'Object with restricted seqs exists in artifact_versions table' using hint = 'Please modify lower and/or upper limit';
        end if;
       
	    insert into {schema_name}.seq_pools (pool_type, pool_status, lower_limit, upper_limit) values ('RESTRICTED','ACTIVE',p_lower_limit,p_upper_limit);
    
	    return 0;
    END;
$function$
;  
