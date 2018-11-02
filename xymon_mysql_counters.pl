[mysql_activity]
    FNPATTERN ^mysql_activity.rrd
    TITLE MySQL Database Activity
    YAXIS avg statements/sec
    DEF:sel@RRDIDX@=@RRDFN@:sel:AVERAGE
    DEF:ins@RRDIDX@=@RRDFN@:ins:AVERAGE
    DEF:upd@RRDIDX@=@RRDFN@:upd:AVERAGE
    DEF:rep@RRDIDX@=@RRDFN@:rep:AVERAGE
    DEF:del@RRDIDX@=@RRDFN@:del:AVERAGE
    DEF:cal@RRDIDX@=@RRDFN@:cal:AVERAGE
    LINE1:sel@RRDIDX@#FF9933:Select
    GPRINT:sel@RRDIDX@:LAST: \: %5.0lf
    LINE1:ins@RRDIDX@#3E9ADE:Insert
    GPRINT:ins@RRDIDX@:LAST: \: %5.0lf
    LINE1:upd@RRDIDX@#FF3300:Update
    GPRINT:upd@RRDIDX@:LAST: \: %5.0lf\l
    LINE1:cal@RRDIDX@#FFCC00:Call
    GPRINT:cal@RRDIDX@:LAST: \: %5.0lf
    LINE1:del@RRDIDX@#990000:Delete
    GPRINT:del@RRDIDX@:LAST: \: %5.0lf
    LINE1:rep@RRDIDX@#80B4C1:Replace
    GPRINT:rep@RRDIDX@:LAST: \: %5.0lf\l

[mysql_command_counters]
    FNPATTERN ^mysql_command_counters.rrd
    TITLE MySQL Command Counters
    YAXIS
    DEF:questions@RRDIDX@=@RRDFN@:questions:AVERAGE
    DEF:select@RRDIDX@=@RRDFN@:select:AVERAGE
    DEF:delete@RRDIDX@=@RRDFN@:delete:AVERAGE
    DEF:insert@RRDIDX@=@RRDFN@:insert:AVERAGE
    DEF:update@RRDIDX@=@RRDFN@:update:AVERAGE
    DEF:replace@RRDIDX@=@RRDFN@:replace:AVERAGE
    DEF:load@RRDIDX@=@RRDFN@:load:AVERAGE
    DEF:delete_multi@RRDIDX@=@RRDFN@:delete_multi:AVERAGE
    DEF:insert_select@RRDIDX@=@RRDFN@:insert_select:AVERAGE
    DEF:update_multi@RRDIDX@=@RRDFN@:update_multi:AVERAGE
    DEF:replace_select@RRDIDX@=@RRDFN@:replace_select:AVERAGE
    AREA:questions@RRDIDX@#FFC3C0:Questions          
    GPRINT:questions@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:questions@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:questions@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:select@RRDIDX@#FF0000:Select             
    GPRINT:select@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:select@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:select@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:delete@RRDIDX@#FF7D00:Delete             
    GPRINT:delete@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:delete@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:delete@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:insert@RRDIDX@#FFF200:Insert             
    GPRINT:insert@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:insert@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:insert@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:update@RRDIDX@#00CF00:Update             
    GPRINT:update@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:update@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:update@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:replace@RRDIDX@#2175D9:Replace            
    GPRINT:replace@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:replace@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:replace@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:load@RRDIDX@#55009D:Load               
    GPRINT:load@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:load@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:load@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:delete_multi@RRDIDX@#942D0C:Delete Multi       
    GPRINT:delete_multi@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:delete_multi@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:delete_multi@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:insert_select@RRDIDX@#AAABA1:Insert Select      
    GPRINT:insert_select@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:insert_select@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:insert_select@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:update_multi@RRDIDX@#D8ACE0:Update Multi       
    GPRINT:update_multi@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:update_multi@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:update_multi@RRDIDX@:MAX: Max\: %4.0lf \n
    AREA:replace_select@RRDIDX@#00B99B:Replace Select     
    GPRINT:replace_select@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:replace_select@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:replace_select@RRDIDX@:MAX: Max\: %4.0lf \n

[mysql_connections]
    FNPATTERN ^mysql_connections.rrd
    TITLE MySQL Connections
    YAXIS
    DEF:max_connections@RRDIDX@=@RRDFN@:max_connections:AVERAGE
    DEF:max_used@RRDIDX@=@RRDFN@:max_used:AVERAGE
    DEF:aborted_clients@RRDIDX@=@RRDFN@:aborted_clients:AVERAGE
    DEF:aborted_connects@RRDIDX@=@RRDFN@:aborted_connects:AVERAGE
    DEF:threads_connected@RRDIDX@=@RRDFN@:threads_connected:AVERAGE
    DEF:threads_running@RRDIDX@=@RRDFN@:threads_running:AVERAGE
    DEF:new_connections@RRDIDX@=@RRDFN@:new_connections:AVERAGE
    AREA:max_connections@RRDIDX@#C0C0C0:Max Connections  
    GPRINT:max_connections@RRDIDX@:AVERAGE: \: %4.0lf
    AREA:max_used@RRDIDX@#FFD660:Max Used         
    GPRINT:max_used@RRDIDX@:AVERAGE: \: %4.0lf \n
    LINE1:aborted_clients@RRDIDX@#FF3932:Aborted Clients  
    GPRINT:aborted_clients@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:aborted_clients@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:aborted_clients@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:aborted_connects@RRDIDX@#00FF00:Aborted Connects 
    GPRINT:aborted_connects@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:aborted_connects@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:aborted_connects@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:threads_connected@RRDIDX@#FF7D00:Threads Connected
    GPRINT:threads_connected@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:threads_connected@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:threads_connected@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:threads_running@RRDIDX@#003300:Threads Running  
    GPRINT:threads_running@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:threads_running@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:threads_running@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:new_connections@RRDIDX@#4444ff:New Connections  
    GPRINT:new_connections@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:new_connections@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:new_connections@RRDIDX@:MAX: Max\: %4.0lf \n

[mysql_files_and_tables]
    FNPATTERN ^mysql_files_and_tables.rrd
    TITLE MySQL Files and Tables
    YAXIS
    DEF:table_open_cache@RRDIDX@=@RRDFN@:table_open_cache:AVERAGE
    DEF:open_tables@RRDIDX@=@RRDFN@:open_tables:AVERAGE
    DEF:opened_files@RRDIDX@=@RRDFN@:opened_files:AVERAGE
    DEF:opened_tables@RRDIDX@=@RRDFN@:opened_tables:AVERAGE
    AREA:table_open_cache@RRDIDX@#96E78A:Table Cache  
    GPRINT:table_open_cache@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:table_open_cache@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:table_open_cache@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:open_tables@RRDIDX@#9FA4EE:Open Tables  
    GPRINT:open_tables@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:open_tables@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:open_tables@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:opened_files@RRDIDX@#FFD660:Open Files   
    GPRINT:opened_files@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:opened_files@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:opened_files@RRDIDX@:MAX: Max\: %4.0lf \n
    LINE1:opened_tables@RRDIDX@#FF0000:Opened Tables
    GPRINT:opened_tables@RRDIDX@:LAST: Current\: %4.0lf
    GPRINT:opened_tables@RRDIDX@:AVERAGE: Average\: %4.0lf
    GPRINT:opened_tables@RRDIDX@:MAX: Max\: %4.0lf \n

[mysql_sorts]
    FNPATTERN ^mysql_sorts.rrd
    TITLE MySQL Sorts
    YAXIS
    DEF:sort_rows@RRDIDX@=@RRDFN@:sort_rows:AVERAGE
    DEF:sort_range@RRDIDX@=@RRDFN@:sort_range:AVERAGE
    DEF:sort_merge_passes@RRDIDX@=@RRDFN@:sort_merge_passes:AVERAGE
    DEF:sort_scan@RRDIDX@=@RRDFN@:sort_scan:AVERAGE
    AREA:sort_rows@RRDIDX@#FFAB00:Rows Sorted 
    GPRINT:sort_rows@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:sort_rows@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:sort_rows@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:sort_range@RRDIDX@#157419:Range       
    GPRINT:sort_range@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:sort_range@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:sort_range@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:sort_merge_passes@RRDIDX@#DA4725:Merge Passes
    GPRINT:sort_merge_passes@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:sort_merge_passes@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:sort_merge_passes@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:sort_scan@RRDIDX@#4444FF:Scan        
    GPRINT:sort_scan@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:sort_scan@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:sort_scan@RRDIDX@:MAX: Max\: %5.0lf \n

[mysql_table_locks]
    FNPATTERN ^mysql_table_locks.rrd
    TITLE MySQL Table Locks
    YAXIS
    DEF:immediate@RRDIDX@=@RRDFN@:immediate:AVERAGE
    DEF:waited@RRDIDX@=@RRDFN@:waited:AVERAGE
    LINE1:immediate@RRDIDX@#002A8F:Table Locks Immediate
    GPRINT:immediate@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:immediate@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:immediate@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:waited@RRDIDX@#FF3932:Table Locks Waited   
    GPRINT:waited@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:waited@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:waited@RRDIDX@:MAX: Max\: %5.0lf \n

[mysql_select_types]
    FNPATTERN ^mysql_select_types.rrd
    TITLE MySQL Select Types
    YAXIS
    DEF:full_join@RRDIDX@=@RRDFN@:full_join:AVERAGE
    DEF:full_range_join@RRDIDX@=@RRDFN@:full_range_join:AVERAGE
    DEF:range@RRDIDX@=@RRDFN@:range:AVERAGE
    DEF:range_check@RRDIDX@=@RRDFN@:range_check:AVERAGE
    DEF:scan@RRDIDX@=@RRDFN@:scan:AVERAGE
    AREA:full_join@RRDIDX@#FF0000:Full Join  
    GPRINT:full_join@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:full_join@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:full_join@RRDIDX@:MAX: Max\: %5.0lf \n
    AREA:full_range_join@RRDIDX@#FF7D00:Full Range 
    GPRINT:full_range_join@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:full_range_join@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:full_range_join@RRDIDX@:MAX: Max\: %5.0lf \n
    AREA:range@RRDIDX@#FFF200:Range      
    GPRINT:range@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:range@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:range@RRDIDX@:MAX: Max\: %5.0lf \n
    AREA:range_check@RRDIDX@#00CF00:Range Check
    GPRINT:range_check@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:range_check@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:range_check@RRDIDX@:MAX: Max\: %5.0lf \n
    AREA:scan@RRDIDX@#7CB3F1:Scan       
    GPRINT:scan@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:scan@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:scan@RRDIDX@:MAX: Max\: %5.0lf \n

[mysql_transaction_handlers]
    FNPATTERN ^mysql_transaction_handlers.rrd
    TITLE MySQL Transaction Handler
    YAXIS
    DEF:commit@RRDIDX@=@RRDFN@:commit:AVERAGE
    DEF:rollback@RRDIDX@=@RRDFN@:rollback:AVERAGE
    DEF:savepoint@RRDIDX@=@RRDFN@:savepoint:AVERAGE
    DEF:savepoint_rollback@RRDIDX@=@RRDFN@:savepoint_rollback:AVERAGE
    LINE1:commit@RRDIDX@#DE0056:Handler Commit             
    GPRINT:commit@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:commit@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:commit@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:rollback@RRDIDX@#784890:Handler Rollback           
    GPRINT:rollback@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:rollback@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:rollback@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:savepoint@RRDIDX@#D1642E:Handler Savepoint          
    GPRINT:savepoint@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:savepoint@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:savepoint@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:savepoint_rollback@RRDIDX@#487860:Handler Savepoint Rollback 
    GPRINT:savepoint_rollback@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:savepoint_rollback@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:savepoint_rollback@RRDIDX@:MAX: Max\: %5.0lf \n

[mysql_temp_objects]
    FNPATTERN ^mysql_temp_objects.rrd
    TITLE MySQL Temporary Objects
    YAXIS
    DEF:tables@RRDIDX@=@RRDFN@:tables:AVERAGE
    DEF:tmp_disk_tables@RRDIDX@=@RRDFN@:tmp_disk_tables:AVERAGE
    DEF:files@RRDIDX@=@RRDFN@:tmp_files:AVERAGE
    AREA:tables@RRDIDX@#837C04:Temp Tables     
    GPRINT:tables@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:tables@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:tables@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:tmp_disk_tables@RRDIDX@#F51D30:Temp Disk Tables
    GPRINT:tmp_disk_tables@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:tmp_disk_tables@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:tmp_disk_tables@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:files@RRDIDX@#157419:Temp Files      
    GPRINT:files@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:files@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:files@RRDIDX@:MAX: Max\: %5.0lf \n

[mysql_query_cache]
    FNPATTERN ^mysql_query_cache.rrd
    TITLE MySQL Query Cache
    YAXIS
    DEF:queries_in_cache@RRDIDX@=@RRDFN@:queries_in_cache:AVERAGE
    DEF:hits@RRDIDX@=@RRDFN@:hits:AVERAGE
    DEF:inserts@RRDIDX@=@RRDFN@:inserts:AVERAGE
    DEF:not_cached@RRDIDX@=@RRDFN@:not_cached:AVERAGE
    DEF:lowmem_prunes@RRDIDX@=@RRDFN@:lowmem_prunes:AVERAGE
    LINE1:queries_in_cache@RRDIDX@#4444FF:Queries In Cache 
    GPRINT:queries_in_cache@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:queries_in_cache@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:queries_in_cache@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:hits@RRDIDX@#EAAF00:Cache Hits       
    GPRINT:hits@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:hits@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:hits@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:inserts@RRDIDX@#157419:Inserts          
    GPRINT:inserts@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:inserts@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:inserts@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:not_cached@RRDIDX@#00A0C1:Not Cached       
    GPRINT:not_cached@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:not_cached@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:not_cached@RRDIDX@:MAX: Max\: %5.0lf \n
    LINE1:lowmem_prunes@RRDIDX@#FF0000:Low-Memory Prunes
    GPRINT:lowmem_prunes@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:lowmem_prunes@RRDIDX@:AVERAGE: Average\: %5.0lf \n

[mysql_handlers]
    FNPATTERN ^mysql_handlers.rrd
    TITLE MySQL Handlers
    YAXIS
    DEF:write@RRDIDX@=@RRDFN@:write:AVERAGE
    DEF:update@RRDIDX@=@RRDFN@:update:AVERAGE
    DEF:delete@RRDIDX@=@RRDFN@:delete:AVERAGE
    DEF:read_first@RRDIDX@=@RRDFN@:read_first:AVERAGE
    DEF:read_key@RRDIDX@=@RRDFN@:read_key:AVERAGE
    DEF:read_next@RRDIDX@=@RRDFN@:read_next:AVERAGE
    DEF:read_prev@RRDIDX@=@RRDFN@:read_prev:AVERAGE
    DEF:read_rnd@RRDIDX@=@RRDFN@:read_rnd:AVERAGE
    DEF:read_rnd_next@RRDIDX@=@RRDFN@:read_rnd_next:AVERAGE
    AREA:write@RRDIDX@#605C59:Handler Write        
    GPRINT:write@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:write@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:write@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:update@RRDIDX@#D2AE84:Handler Update       
    GPRINT:update@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:update@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:update@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:delete@RRDIDX@#C9C5C0:Handler Delete       
    GPRINT:delete@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:delete@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:delete@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:read_first@RRDIDX@#9F3E81:Handler Read First   
    GPRINT:read_first@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:read_first@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:read_first@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:read_key@RRDIDX@#C6BE91:Handler Read Key     
    GPRINT:read_key@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:read_key@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:read_key@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:read_next@RRDIDX@#CE3F53:Handler Read Next    
    GPRINT:read_next@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:read_next@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:read_next@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:read_prev@RRDIDX@#FD7F00:Handler Read Prev    
    GPRINT:read_prev@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:read_prev@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:read_prev@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:read_rnd@RRDIDX@#6E4E40:Handler Read Rnd     
    GPRINT:read_rnd@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:read_rnd@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:read_rnd@RRDIDX@:MAX: Max\: %6.0lf \n
    AREA:read_rnd_next@RRDIDX@#79DAEC:Handler Read Rnd Next
    GPRINT:read_rnd_next@RRDIDX@:LAST: Current\: %6.0lf
    GPRINT:read_rnd_next@RRDIDX@:AVERAGE: Average\: %6.0lf
    GPRINT:read_rnd_next@RRDIDX@:MAX: Max\: %6.0lf \n

[mysql_prepared_statements]
    FNPATTERN ^mysql_prepared_statements.rrd
    TITLE MySQL Prepared Statements
    YAXIS
    DEF:stmt_count@RRDIDX@=@RRDFN@:stmt_count:AVERAGE
    LINE1:stmt_count@RRDIDX@#4444FF:Prepared Statement Count
    GPRINT:stmt_count@RRDIDX@:LAST: Current\: %5.0lf
    GPRINT:stmt_count@RRDIDX@:AVERAGE: Average\: %5.0lf
    GPRINT:stmt_count@RRDIDX@:MAX: Max\: %5.0lf \n
