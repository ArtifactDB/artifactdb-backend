CREATE OR REPLACE FUNCTION {schema_name}.curr_seq()
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
    declare seq_val int4;
    	    exist_val int4;
    begin

        select max(artifact_seq) from {schema_name}.artifact_versions into exist_val;
        return exist_val;
    END;
$function$
;
