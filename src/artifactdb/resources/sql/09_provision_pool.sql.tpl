CREATE OR REPLACE FUNCTION {schema_name}.provision_pool(p_lower_limit int4, p_upper_limit int4)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
    begin
        
	    if p_lower_limit >= p_upper_limit then
            raise exception 'Upper pool seq limit should be greater than lower limit' using hint = 'Please modify parameters';
        end if;
       
        lock table {schema_name}.seq_pools in access exclusive mode;
	   
	    update {schema_name}.seq_pools set pool_status = 'INACTIVE' where pool_type = 'PROVISIONED';
        
	    insert into {schema_name}.seq_pools (pool_type, pool_status, lower_limit, upper_limit) values ('PROVISIONED','ACTIVE',p_lower_limit,p_upper_limit);
    
	    return 0;
    END;
$function$
;   
