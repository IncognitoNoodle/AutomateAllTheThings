declare @objname nvarchar(776) = '_view_All_bond_MI'  -- the object we want to check    
  
declare @objid int   -- the id of the object we want  
declare @found_some bit   -- flag for dependencies found  
declare @dbname sysname  
  
  
--  Make sure the @objname is local to the current database.  
  
select @dbname = parsename(@objname,3)  
  
if @dbname is not null and @dbname <> db_name()  
 begin  
  raiserror(15250,-1,-1)  
  --return (1)  
 end  
  
--  See if @objname exists.  
select @objid = object_id(@objname)  
if @objid is null  
 begin  
  select @dbname = db_name()  
  raiserror(15009,-1,-1,@objname,@dbname)  
  --return (1)  
 end  
  
--  Initialize @found_some to indicate that we haven't seen any dependencies.  
select @found_some = 0  
  
set nocount on  
  
--  Print out the particulars about the local dependencies.  
if exists (select *  
  from sysdepends  
   where id = @objid)  
begin  
 raiserror(15459,-1,-1)  
 select   'name' = (s6.name+ '.' + o1.name),  
    type = substring(v2.name, 5, 66),  -- spt_values.name is nvarchar(70)  
    updated = substring(u4.name, 1, 7),  
    selected = substring(w5.name, 1, 8),  
             'column' = col_name(d3.depid, d3.depnumber)  
  from  sys.objects  o1  
   ,master.dbo.spt_values v2  
   ,sysdepends  d3  
   ,master.dbo.spt_values u4  
   ,master.dbo.spt_values w5 --11667  
   ,sys.schemas  s6  
  where  o1.object_id = d3.depid  
  and  o1.type = substring(v2.name,1,2) collate catalog_default and v2.type = 'O9T'  
  and  u4.type = 'B' and u4.number = d3.resultobj  
  and  w5.type = 'B' and w5.number = d3.readobj|d3.selall  
  and  d3.id = @objid  
  and  o1.schema_id = s6.schema_id  
  and deptype < 2  
  and o1.type in ('V', 'P')
  
 select @found_some = 1  
end  
  
--  Now check for things that depend on the object.  
--if exists (select *  
--  from sysdepends  
--   where depid = @objid)  
--begin  
--  raiserror(15460,-1,-1)  
-- select distinct 'name' = (s.name + '.' + o.name),  
--  type = substring(v.name, 5, 66)    -- spt_values.name is nvarchar(70)  
--   from sys.objects o, master.dbo.spt_values v, sysdepends d,  
--    sys.schemas s  
--   where o.object_id = d.id  
--    and o.type = substring(v.name,1,2) collate catalog_default and v.type = 'O9T'  
--    and d.depid = @objid  
--    and o.schema_id = s.schema_id  
--    and deptype < 2  
  
-- select @found_some = 1  
--end  
  
--  Did we find anything in sysdepends?  
if @found_some = 0  
 raiserror(15461,-1,-1)  
  
set nocount off  
  
--return (0) 