CREATE OR REPLACE FUNCTION {schema_name}.next_version_seq(p_artifact_seq int4)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
	declare version_num int4;
			artifact_exists bool; 
            max_de_seq int4;
            ds_ver_exists bool;
	begin
		
		select exists(select 1 from {schema_name}.artifact_versions where artifact_seq = p_artifact_seq) into artifact_exists;

        select max(artifact_seq) from {schema_name}.artifact_versions into max_de_seq;

        if not artifact_exists and p_artifact_seq <> max_de_seq then
            RAISE EXCEPTION 'INVALID PROJECT IDENTIFIER--> %', p_artifact_seq USING HINT = 'Please use identifier of an existing project';
        end if;

        select curr_version_num from {schema_name}.artifact_versions where artifact_seq = p_artifact_seq into version_num;
	
	    if artifact_exists then
	    	update {schema_name}.artifact_versions set curr_version_num = curr_version_num+1 where artifact_seq = p_artifact_seq returning  curr_version_num into  version_num;
	    	return version_num;
	    else
	    	insert into {schema_name}.artifact_versions (artifact_seq, curr_version_num) values (p_artifact_seq, 1);
	    	return 1;
	    end if;
		commit;
	END;
$function$
;
