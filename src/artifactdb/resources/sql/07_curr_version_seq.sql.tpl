CREATE OR REPLACE FUNCTION {schema_name}.curr_version_seq(p_artifact_seq int4)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
	declare version_num int4;
			artifact_exists bool; 
	begin
		
		select exists(select 1 from {schema_name}.artifact_versions where artifact_seq = p_artifact_seq) into artifact_exists;
	
	    if artifact_exists then
            select curr_version_num from {schema_name}.artifact_versions where artifact_seq = p_artifact_seq into version_num;
            return version_num;
	    else
	    	return null;
	    end if;
	END;
$function$
;

