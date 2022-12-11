/*
  Copyright 2022 Bo Lindbergh
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

static char const * const encoding_names[] =
{
    NULL,
    "UTF-8",
    "UTF-16le",
    "UTF-16be"
};

static char const * const copy_pragma_names[] =
{
    "page_size",
    "auto_vacuum",
    "application_id",
    "user_version"
};

enum {
    copy_pragma_count = sizeof copy_pragma_names/sizeof copy_pragma_names[0]
};

typedef struct column_info {
    char *name;
    char include;
} column_info;

typedef struct table_info {
    char *name;
    int name_length;
    char internal;
    char clear;
    size_t column_count;
    size_t included_column_count;
    column_info *columns;
} table_info;

/*
  The rest of the code assumes that user tables come before
  internal tables and that the sqlite_sequence table comes last.
*/

static char const list_tables_sql[] =
    "select name,"
    "  name like 'sqlite_%' as internal,"
    "  name collate nocase in ('sqlite_sequence') as clear"
    " from sqlite_schema"
    " where type='table' and rootpage>0"
    " order by internal, clear, name collate nocase;";

static char const create_omit_sql[] =
    "create table temp.omit ("
    " table_name text collate nocase,"
    " column_name text collate nocase,"
    " primary key (table_name, column_name))"
    " without rowid;";

/*
  We want to avoid complaints from pragma foreign_key_check,
  so for each foreign key reference, add both the referenced and
  the referencing column to the set of columns not to touch.

  Unfortunately, pragma foreign_key_list returns null names for referenced
  columns whenever the constraint clause omits them.  Thus, we need an extra
  common table containing the primary key column names for each table.
*/

static char const fill_omit_sql[] =
    "with"
    " fki (from_table, from_column, to_table, to_column, key_rank) as"
    "  (select name, \"from\", \"table\", \"to\", seq"
    "    from sqlite_schema ss,"
    "     temp.pragma_foreign_key_list(ss.name)"
    "    where ss.type='table'),"
    " tpk (table_name, key_rank, column_name) as"
    "  (select ss.name, ii.seqno, ii.name"
    "    from sqlite_schema ss,"
    "     temp.pragma_index_list(ss.name) il,"
    "     temp.pragma_index_info(il.name) ii"
    "    where il.origin='pk' and ii.name is not null)"
    "insert into temp.omit"
    " select from_table, from_column from fki"
    " union select to_table, to_column from fki"
    "  where to_column is not null"
    " union select fki.to_table, tpk.column_name"
    "  from fki,"
    "   tpk on tpk.table_name=fki.to_table and tpk.key_rank=fki.key_rank"
    "  where fki.to_column is null;"
    ;

static char const drop_omit_sql[] =
    "drop table temp.omit;";

static char const list_columns_sql[] =
    "select cl.name as name,"
    "  (?1, cl.name) not in temp.omit as include"
    "  from temp.pragma_table_info(?1) cl"
    " order by cl.cid;";

static char const begin_read_transaction_sql[] =
    "begin deferred transaction;";

static char const begin_write_transaction_sql[] =
    "begin immediate transaction;";

static char const commit_transaction_sql[] =
    "commit transaction;";

static char const rollback_transaction_sql[] =
    "rollback transaction;";

static char const pragma_get_encoding_sql[] =
    "pragma encoding;";

static char const named_pragma_get_sql[] =
    "pragma %s;";

static char const named_pragma_set_sql[] =
    "pragma %s=%lld;";

static char const pragma_set_foreign_keys_off_sql[] =
    "pragma foreign_keys=0;";

static char const pragma_get_page_count_sql[] =
    "pragma page_count;";

static char const pragma_set_encoding_sql[] =
    "pragma encoding=%Q;";

static char const get_table_sql[] =
    "select sql from sqlite_schema"
    " where name=?1 and type='table' and rootpage>0;";

static char const pragma_set_writable_schema_on_sql[] =
    "pragma writable_schema=1;";

static char const pragma_set_writable_schema_off_sql[] =
    "pragma writable_schema=0;";

static char const pragma_set_writable_schema_reset_sql[] =
    "pragma writable_schema=reset;";

static char named_delete_from_sql[] =
    "delete from \"%w\";";

static char const list_objects_sql[] =
    "select sql from sqlite_schema"
    " where type=?1 and sql is not null;";

static char const list_virtuals_sql[] =
    "select name, sql from sqlite_schema"
    " where type='table' and coalesce(rootpage, 0)=0;";

static char const create_virtual_sql[] =
    "insert into sqlite_schema (type, name, tbl_name, rootpage, sql)"
    " values ('table', ?1, ?1, 0, ?2);";

static char *source_name;
static sqlite3 *source_db=NULL;
static int source_encoding=-1;
static sqlite3_stmt *list_objects=NULL;

static char *insert_name=NULL;
static FILE *insert_file;

static char *extract_name=NULL;
static FILE *extract_file=NULL;

static char *destination_name=NULL;
static sqlite3 *destination_db=NULL;
static int destination_encoding=-1;

static sqlite_int64 pragma_values[copy_pragma_count];

static table_info *tables;
static size_t table_count;
static size_t user_table_count;
static size_t internal_table_count;
static size_t max_included;

static sqlite3_uint64 space_avail;
static sqlite3_uint64 space_used;
static sqlite3_uint64 space_wanted;

static void fatal(
    char const *format,
    ...)
{
    va_list args;

    va_start(args,format);
    vfprintf(stderr,format,args);
    va_end(args);
    exit(1);
}

static void *malloc_or_die(
    size_t size)
{
    void *result;

    if (!size)
        return NULL;
    result=sqlite3_malloc64(size);
    if (!result)
        fatal("sqlite3_malloc failed\n");
    return result;
}

static char *mprintf_or_die(
    char const *format,
    ...)
{
    va_list args;
    char *result;

    va_start(args,format);
    result=sqlite3_vmprintf(format,args);
    va_end(args);
    if (!result)
        fatal("sqlite3_mprintf failed\n");
    return result;
}

static char *str_or_die(
    sqlite3_str *str)
{
    int status;

    status=sqlite3_str_errcode(str);
    if (status!=SQLITE_OK)
        fatal("sqlite_str: %s\n",sqlite3_errstr(status));
    return sqlite3_str_finish(str);
}

static void prepare_or_die(
    sqlite3 *db,
    char const *sql,
    sqlite3_stmt **stmt)
{
    int status;

    status=sqlite3_prepare_v2(db,sql,-1,stmt,NULL);
    if (status!=SQLITE_OK)
        fatal("sqlite3_prepare: %s\n(%s)\n",sqlite3_errmsg(db),sql);
}

static void run_or_die(
    sqlite3 *db,
    char const *sql)
{
    int status;
    sqlite3_stmt *stmt;

    prepare_or_die(db,sql,&stmt);
    status=sqlite3_step(stmt);
    if (status!=SQLITE_DONE)
        fatal("sqlite3_step: %s\n(%s)\n",sqlite3_errmsg(db),sql);
    sqlite3_finalize(stmt);
}

static sqlite3_int64 run_or_die_int(
    sqlite3 *db,
    char const *sql)
{
    int status;
    sqlite3_stmt *stmt;
    sqlite3_int64 result;

    prepare_or_die(db,sql,&stmt);
    status=sqlite3_step(stmt);
    if (status!=SQLITE_ROW)
        fatal("sqlite3_step: %s\n(%s)\n",sqlite3_errmsg(db),sql);
    result=sqlite3_column_int64(stmt,0);
    sqlite3_finalize(stmt);
    return result;
}

static char *run_or_die_str(
    sqlite3 *db,
    char const *sql)
{
    int status;
    sqlite3_stmt *stmt;
    unsigned char const *text;
    size_t size;
    char *result;

    prepare_or_die(db,sql,&stmt);
    status=sqlite3_step(stmt);
    if (status!=SQLITE_ROW)
        fatal("sqlite3_step: %s\n(%s)\n",sqlite3_errmsg(db),sql);
    text=sqlite3_column_text(stmt,0);
    if (!text)
        fatal("sqlite3_column_text failed\n");
    size=sqlite3_column_bytes(stmt,0);
    result=malloc_or_die(size+1);
    memcpy(result,text,size+1);
    sqlite3_finalize(stmt);
    return result;
}

static int step_or_die(
    sqlite3_stmt *stmt)
{
    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 1;
    case SQLITE_DONE:
        return 0;
    }
    fatal("sqlite3_step: %s\n(%s)\n",
          sqlite3_errmsg(sqlite3_db_handle(stmt)),
          sqlite3_sql(stmt));
    return -1;
}

static void open_source(void)
{
    int status;
    char *enc;
    static int encix;
    unsigned int pragma_index;

    status=sqlite3_open_v2(
        source_name,&source_db,SQLITE_OPEN_READONLY,NULL);
    if (status!=SQLITE_OK) {
        if (source_db) {
            fatal("%s: sqlite3_open: %s\n",
                    source_name,sqlite3_errmsg(source_db));
        } else {
            fatal("%s: sqlite3_open: %s\n",
                  source_name,sqlite3_errstr(status));
        }
    }

    run_or_die(source_db,begin_read_transaction_sql);

    enc=run_or_die_str(source_db,pragma_get_encoding_sql);
    for (encix=SQLITE_UTF8; encix<=SQLITE_UTF16BE; encix++) {
        if (!strcmp(enc,encoding_names[encix])) {
            source_encoding=encix;
            break;
        }
    }
    if (source_encoding<0)
        fatal("%s: Unknown text encoding %s\n",source_name,enc);
    sqlite3_free(enc);

    for (pragma_index=0; pragma_index<copy_pragma_count; pragma_index++) {
        char *sql;

        sql=mprintf_or_die(
            named_pragma_get_sql,copy_pragma_names[pragma_index]);
        pragma_values[pragma_index]=run_or_die_int(source_db,sql);
        sqlite3_free(sql);
    }

    prepare_or_die(source_db,list_objects_sql,&list_objects);
}

static void close_source(void)
{
    size_t table_index;

    sqlite3_finalize(list_objects);
    list_objects=NULL;
    for (table_index=0; table_index<table_count; table_index++)
        free(tables[table_index].columns);
    free(tables);
    tables=NULL;
    table_count=0;
    sqlite3_exec(source_db,rollback_transaction_sql,0,NULL,NULL);
    sqlite3_close_v2(source_db);
    source_db=NULL;
}

static void load_columns(
    table_info *table,
    sqlite3_stmt *list_columns)
{
    int status;
    size_t column_count,included_column_count;
    size_t column_names_size,column_names_offset;
    column_info *columns,*columns_end,*column;
    char *column_names;

    status=sqlite3_bind_text(
        list_columns,1,table->name,table->name_length,SQLITE_STATIC);
    if (status!=SQLITE_OK)
        fatal("sqlite3_bind_text: %s\n",sqlite3_errmsg(source_db));

    column_count=0;
    column_names_size=0;
    while (step_or_die(list_columns)) {
        unsigned char const *name;

        name=sqlite3_column_text(list_columns,0);
        if (!name)
            fatal("sqlite3_column_text failed\n");
        column_names_size+=sqlite3_column_bytes(list_columns,0)+1;
        column_count++;
    }
    sqlite3_reset(list_columns);

    columns=malloc_or_die(
        column_count*sizeof (column_info)+column_names_size);
    columns_end=columns+column_count;
    column=columns;
    column_names=(char *)(columns+column_count);
    column_names_offset=0;
    included_column_count=0;
    while (step_or_die(list_columns)) {
        unsigned char const *name;
        size_t size;

        if (column>=columns_end)
            fatal("Inconsistent column count\n");
        name=sqlite3_column_text(list_columns,0);
        if (!name)
            fatal("sqlite3_column_text failed\n");
        size=sqlite3_column_bytes(list_columns,0)+1;
        if (column_names_offset+size>column_names_size)
            fatal("Inconsistent column names\n");
        memcpy(column_names+column_names_offset,name,size);
        column->name=column_names+column_names_offset;
        column->include=sqlite3_column_int64(list_columns,1)!=0;
        if (column->include)
            included_column_count++;
        column_names_offset+=size;
        column++;
    }
    sqlite3_reset(list_columns);

    table->columns=columns;
    table->column_count=column_count;
    table->included_column_count=included_column_count;
}

static void load_tables(void)
{ 
    sqlite3_stmt *list_tables=NULL;
    sqlite3_stmt *list_columns=NULL;
    char *table_names;
    size_t table_names_size,table_names_offset;
    table_info *tables_end,*table;

    run_or_die(source_db,create_omit_sql);
    run_or_die(source_db,fill_omit_sql);
    prepare_or_die(source_db,list_tables_sql,&list_tables);
    prepare_or_die(source_db,list_columns_sql,&list_columns);

    table_names_size=0;
    while (step_or_die(list_tables)) {
        unsigned char const *name;

        name=sqlite3_column_text(list_tables,0);
        if (!name)
            fatal("sqlite3_column_value failed\n");
        table_names_size+=sqlite3_column_bytes(list_tables,0)+1;
        table_count++;
    }
    sqlite3_reset(list_tables);

    tables=malloc_or_die(table_count*sizeof (table_info)+table_names_size);
    tables_end=tables+table_count;
    table=tables;
    table_names=(char *)(tables+table_count);
    table_names_offset=0;
    while (step_or_die(list_tables)) {
        unsigned char const *name;
        size_t size;

        if (table>=tables_end)
            fatal("Inconsistent table count\n");
        name=sqlite3_column_text(list_tables,0);
        if (!name)
            fatal("sqlite3_column_value failed\n");
        size=sqlite3_column_bytes(list_tables,0)+1;
        if (table_names_offset+size>table_names_size)
            fatal("Inconsistent table names\n");
        memcpy(table_names+table_names_offset,name,size);
        table->name=table_names+table_names_offset;
        table->name_length=size-1;
        table->internal=sqlite3_column_int64(list_tables,1)!=0;
        table->clear=sqlite3_column_int64(list_tables,2)!=0;
        table_names_offset+=size;
        if (table->internal) {
            internal_table_count++;
        } else {
            user_table_count++;
        }
        load_columns(table,list_columns);
        if (table->included_column_count>max_included)
            max_included=table->included_column_count;
        table++;
    }
    if (table<tables_end)
        fatal("Inconsistent table count\n");

    sqlite3_finalize(list_columns);
    sqlite3_finalize(list_tables);
    run_or_die(source_db,drop_omit_sql);
}

typedef void const *(*value_text_func)(sqlite3_value *val);

typedef int (*value_bytes_func)(sqlite3_value *val);

static void const *value_text8(
    sqlite3_value *val)
{
    return sqlite3_value_text(val);
}

static int value_bytes16(
    sqlite3_value *val)
{
    return sqlite3_value_bytes16(val) & ~1;
}

static void examine_data(void)
{
    value_text_func value_text;
    table_info *tables_end,*table;

    switch (source_encoding) {
    case SQLITE_UTF16BE:
        value_text=sqlite3_value_text16be;
        break;
    case SQLITE_UTF16LE:
        value_text=sqlite3_value_text16le;
        break;
    default:
        value_text=sqlite3_value_text16;
        break;
    }
    tables_end=tables+user_table_count;
    for (table=tables; table<tables_end; table++) {
        column_info *columns,*columns_end,*column;
        size_t included_count,column_index;
        sqlite3_str *fetch_rows_str=NULL;
        char *sql;
        sqlite3_stmt *fetch_rows=NULL;

        if (!table->included_column_count)
            continue;
        columns=table->columns;
        columns_end=columns+table->column_count;
        fetch_rows_str=sqlite3_str_new(source_db);
        sqlite3_str_appendall(fetch_rows_str,"select ");
        included_count=0;
        for (column=columns; column<columns_end; column++) {
            if (column->include) {
                if (included_count>0)
                    sqlite3_str_appendchar(fetch_rows_str,1,',');
                sqlite3_str_appendf(fetch_rows_str,"\"%w\"",column->name);
                included_count++;
            }
        }
        sqlite3_str_appendf(
            fetch_rows_str," from \"%w\";",table->name);
        sql=str_or_die(fetch_rows_str);
        prepare_or_die(source_db,sql,&fetch_rows);
        sqlite3_free(sql);
        while (step_or_die(fetch_rows)) {
            for (column_index=0; column_index<included_count; column_index++) {
                sqlite3_value *val;

                val=sqlite3_column_value(fetch_rows,column_index);
                if (!val)
                    fatal("sqlite3_column_value failed\n");
                if (sqlite3_value_type(val)==SQLITE_TEXT) {
                    int size;

                    space_avail++;
                    size=sqlite3_value_bytes16(val);
                    if (size&1) {
                        space_used++;
                        if (extract_file) {
                            unsigned char const *text;

                            text=(*value_text)(val);
                            if (!text)
                                fatal("sqlite3_value_text16 failed\n");
                            putc(text[size-1],extract_file);
                        }
                    }
                }
            }
        }
        sqlite3_finalize(fetch_rows);
    }
}

static void open_extract(void)
{
    if (extract_name) {
        if (!strcmp(extract_name,"-")) {
            extract_file=stdout;
            extract_name="<stdout>";
        } else {
            extract_file=fopen(extract_name,"wb");
            if (!extract_file)
                fatal("%s: fopen failed\n",extract_name);
        }
    }
}

static void close_extract(void)
{
    if (extract_file) {
        if (fclose(extract_file))
            fatal("%s: fclose failed\n",extract_name);
        extract_file=NULL;
    }
}

static void report(void)
{
    if (!extract_name && !destination_name) {
        printf("%llu/%llu\n",
               (unsigned long long)space_used,
               (unsigned long long)space_avail);
    }
}

static void open_insert(void)
{
    if (insert_name) {
        if (!strcmp(insert_name,"-")) {
            insert_file=stdin;
            insert_name="<stdin>";
        } else {
            insert_file=fopen(insert_name,"rb");
            if (!insert_file)
                fatal("%s: fopen failed\n",insert_name);
        }
        if (fseek(insert_file,0,SEEK_END))
            fatal("%s: Unable to determine file size\n",insert_name);
        space_wanted=ftell(insert_file);
        if (space_wanted==(sqlite3_uint64)-1L)
            fatal("%s: Unable to determine file size\n",insert_name);
        if (!space_wanted)
            fatal("%s: This file seems to be empty\n",insert_name);
        rewind(insert_file);
        if (space_wanted>space_avail)
            fatal("Insufficient steganographic space (%llu<%llu)\n",
                  (unsigned long long)space_avail,
                  (unsigned long long)space_wanted);
    }
}

static void close_insert(void)
{
    if (insert_file) {
        if (insert_file!=stdin)
            fclose(insert_file);
        insert_file=NULL;
    }
}

static int big_endian(void)
{
    static union {
        unsigned char b[2];
        unsigned short w;
    } const u={
        {0x12, 0x34}
    };

    return u.w==0x1234; /* Guess what both Clang and GCC optimise this to. */
}

static void open_destination(void)
{
    int status;
    char *sql,*enc;
    size_t pragma_index;

    status=sqlite3_open_v2(
        destination_name,
        &destination_db,
        SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE,
        NULL);
    if (status!=SQLITE_OK) {
        if (source_db) {
            fatal("%s: sqlite3_open: %s\n",
                    destination_name,sqlite3_errmsg(destination_db));
        } else {
            fatal("%s: sqlite3_open: %s\n",
                    destination_name,sqlite3_errstr(status));
        }
    }
    status=sqlite3_db_config(
        destination_db,SQLITE_DBCONFIG_DEFENSIVE,0,NULL);
    if (status!=SQLITE_OK)
        fatal("Failed to turn off defensive mode: %s\n",
              sqlite3_errmsg(destination_db));

    switch (destination_encoding) {
    case SQLITE_UTF8:
    case SQLITE_UTF16LE:
    case SQLITE_UTF16BE:
        break;
    default:
        if (source_encoding==SQLITE_UTF8 && insert_name) {
        case SQLITE_UTF16:
            destination_encoding=
                big_endian() ? SQLITE_UTF16BE : SQLITE_UTF16LE;
        } else {
            destination_encoding=source_encoding;
        }
    }
    sql=mprintf_or_die(
        pragma_set_encoding_sql,encoding_names[destination_encoding]);
    run_or_die(destination_db,sql);
    sqlite3_free(sql);

    run_or_die(destination_db,pragma_set_foreign_keys_off_sql);

    for (pragma_index=0; pragma_index<copy_pragma_count; pragma_index++) {
        sql=mprintf_or_die(
            named_pragma_set_sql,
            copy_pragma_names[pragma_index],
            pragma_values[pragma_index]);
        run_or_die(destination_db,sql);
        sqlite3_free(sql);
    }

    run_or_die(destination_db,begin_write_transaction_sql);

    /*
      There's an unavoidable race condition here, since the
      page_size and auto_vacuum pragmas must be run *before* any
      transaction.  Read back the values we just set to see
      if we lost the race.
    */

    for (pragma_index=0; pragma_index<copy_pragma_count; pragma_index++) {
        sql=mprintf_or_die(
            named_pragma_get_sql,copy_pragma_names[pragma_index]);
        if (run_or_die_int(destination_db,sql)!=pragma_values[pragma_index])
            fatal("%s: Database already exists\n",destination_name);
        sqlite3_free(sql);
    }

    if (run_or_die_int(destination_db,pragma_get_page_count_sql)!=1)
        fatal("%s: Database already exists\n",destination_name);

    enc=run_or_die_str(destination_db,pragma_get_encoding_sql);
    if (strcmp(enc,encoding_names[destination_encoding]))
        fatal("%s: Database already exists\n",destination_name);
    sqlite3_free(enc);
}

static void close_destination(void)
{
    run_or_die(destination_db,commit_transaction_sql);
    sqlite3_close_v2(destination_db);
    destination_db=NULL;
}

static void create_one_table(
    table_info *table,
    sqlite3_stmt *get_table)
{
    int status;
    char const *sql;

    status=sqlite3_bind_text(
        get_table,1,table->name,table->name_length,SQLITE_STATIC);
    if (status!=SQLITE_OK)
        fatal("sqlite3_bind_text: %s\n",sqlite3_errmsg(source_db));

    status=sqlite3_step(get_table);
    if (status!=SQLITE_ROW)
        fatal("sqlite3_step: %s\n(%s)\n",
              sqlite3_errmsg(source_db),get_table_sql);
    sql=(char const *)sqlite3_column_text(get_table,0);
    if (!sql)
        fatal("sqlite3_column_text failed\n");
    run_or_die(destination_db,sql);

    sqlite3_reset(get_table);
    sqlite3_clear_bindings(get_table);
}

static void create_tables(void)
{
    sqlite3_stmt *get_table;
    table_info *user_tables_end,*table;

    if (!table_count)
        return;
    prepare_or_die(source_db,get_table_sql,&get_table);
    user_tables_end=tables+user_table_count;
    if (internal_table_count>0) {
        run_or_die(destination_db,pragma_set_writable_schema_on_sql);
        for (table=tables+table_count; table-->user_tables_end; )
            create_one_table(table,get_table);
        run_or_die(destination_db,pragma_set_writable_schema_off_sql);
    }
    for (table=tables; table<user_tables_end; table++)
        create_one_table(table,get_table);
    sqlite3_finalize(get_table);
}

static int randomly_insert(void)
{
    sqlite3_uint64 r;

    if (!space_avail)
        return 0;
    sqlite3_randomness(sizeof r,&r);
    if (r%space_avail--<space_wanted) {
        space_wanted--;
        return 1;
    }
    return 0;
}

static void copy_data(void)
{
    value_bytes_func value_bytes;
    value_text_func value_text;
    int status;
    table_info *tables_end,*table;
    char **copies;
    size_t copy_count;

    if (max_included>0) {
        copies=malloc_or_die(max_included*sizeof (char *));
    } else {
        copies=NULL;
    }
    switch (destination_encoding) {
    case SQLITE_UTF8:
        value_bytes=sqlite3_value_bytes;
        value_text=value_text8;
        break;
    case SQLITE_UTF16LE:
        value_bytes=value_bytes16;
        value_text=sqlite3_value_text16le;
        break;
    case SQLITE_UTF16BE:
        value_bytes=value_bytes16;
        value_text=sqlite3_value_text16be;
        break;
    }
    tables_end=tables+table_count;
    for (table=tables; table<tables_end; table++) {
        column_info *columns,*columns_end,*column;
        size_t column_count,column_index;
        sqlite3_str *fetch_rows_str,*store_row_str;
        char *sql;
        sqlite3_stmt *fetch_rows,*store_row;

        if (table->clear) {
            sql=mprintf_or_die(named_delete_from_sql,table->name);
            run_or_die(destination_db,sql);
            sqlite3_free(sql);
        }
        columns=table->columns;
        column_count=table->column_count;
        columns_end=columns+column_count;
        fetch_rows_str=sqlite3_str_new(source_db);
        store_row_str=sqlite3_str_new(destination_db);
        sqlite3_str_appendall(fetch_rows_str,"select ");
        sqlite3_str_appendf(
            store_row_str,"insert into \"%w\" (",table->name);
        column_index=0;
        for (column=columns; column<columns_end; column++) {
            if (column_index++>0) {
                sqlite3_str_appendchar(fetch_rows_str,1,',');
                sqlite3_str_appendchar(store_row_str,1,',');
            }
            sqlite3_str_appendf(
                fetch_rows_str,"\"%w\"",column->name);
            sqlite3_str_appendf(
                store_row_str,"\"%w\"",column->name);
        }
        sqlite3_str_appendf(
            fetch_rows_str," from \"%w\";",table->name);
        sqlite3_str_appendall(store_row_str,") values (");
        for (column_index=0; column_index<column_count; column_index++) {
            if (column_index>0)
                sqlite3_str_appendchar(store_row_str,1,',');
            sqlite3_str_appendchar(store_row_str,1,'?');
        }
        sqlite3_str_appendall(store_row_str,");");

        sql=str_or_die(fetch_rows_str);
        prepare_or_die(source_db,sql,&fetch_rows);
        sqlite3_free(sql);

        sql=str_or_die(store_row_str);
        prepare_or_die(destination_db,sql,&store_row);
        sqlite3_free(sql);

        while (step_or_die(fetch_rows)) {
            copy_count=0;
            column_index=0;
            for (column=columns; column<columns_end; column++) {
                sqlite3_value *val;

                val=sqlite3_column_value(fetch_rows,column_index);
                if (!val)
                    fatal("sqlite3_column_value failed\n");
                if (!table->internal && column->include
                        && sqlite3_value_type(val)==SQLITE_TEXT) {
                    char const *text;
                    char *copy=NULL;
                    int size;

                    size=(*value_bytes)(val);
                    text=(char const *)(*value_text)(val);
                    if (!text)
                        fatal("sqlite3_value_text* failed\n");
                    if (insert_file && randomly_insert()) {
                        int c;

                        copy=malloc_or_die(size+1);
                        copies[copy_count++]=copy;
                        memcpy(copy,text,size);
                        c=getc(insert_file);
                        if (c==EOF)
                            fatal("%s: Unexpected EOF\n",insert_name);
                        copy[size++]=c;
                        text=copy;
                    }
                    status=sqlite3_bind_text64(
                        store_row,column_index+1,
                        text,size,
                        SQLITE_STATIC,
                        destination_encoding);
                    if (status!=SQLITE_OK)
                        fatal("sqlite3_bind_text64: %s\n",
                                sqlite3_errmsg(destination_db));
                } else {
                    status=sqlite3_bind_value(store_row,column_index+1,val);
                    if (status!=SQLITE_OK)
                        fatal("sqlite3_bind_value: %s\n",
                                sqlite3_errmsg(destination_db));
                }
                column_index++;
            }
            status=sqlite3_step(store_row);
            if (status!=SQLITE_DONE)
                fatal("sqlite3_step: %s\n",sqlite3_errmsg(destination_db));
            sqlite3_reset(store_row);
            sqlite3_clear_bindings(store_row);
            while (copy_count-->0)
                sqlite3_free(copies[copy_count]);
        }
        sqlite3_finalize(fetch_rows);
        sqlite3_finalize(store_row);
    }
    sqlite3_free(copies);
}

static void create_objects(
    char const *type)
{
    int status;

    status=sqlite3_bind_text(list_objects,1,type,-1,SQLITE_STATIC);
    if (status!=SQLITE_OK)
        fatal("sqlite3_bind_text: %s\n",sqlite3_errmsg(source_db));
    while (step_or_die(list_objects)) {
        char const *sql;

        sql=(char const *)sqlite3_column_text(list_objects,0);
        if (!sql)
            fatal("sqlite3_column_text failed\n");
        run_or_die(destination_db,sql);
    }
    sqlite3_reset(list_objects);
    sqlite3_clear_bindings(list_objects);
}

static void create_virtuals(void)
{
    int status;
    sqlite3_stmt *list_virtuals;
    sqlite3_stmt *create_virtual;

    run_or_die(destination_db,pragma_set_writable_schema_on_sql);
    prepare_or_die(source_db,list_virtuals_sql,&list_virtuals);
    prepare_or_die(destination_db,create_virtual_sql,&create_virtual);
    while (step_or_die(list_virtuals)) {
        sqlite3_value *name,*sql;

        name=sqlite3_column_value(list_virtuals,0);
        if (!name)
            fatal("sqlite3_column_value failed\n");
        sql=sqlite3_column_value(list_virtuals,1);
        if (!sql)
            fatal("sqlite3_column_value failed\n");
        status=sqlite3_bind_value(create_virtual,1,name);
        if (status!=SQLITE_OK)
            fatal("sqlite3_bind_value failed\n");
        status=sqlite3_bind_value(create_virtual,2,sql);
        if (status!=SQLITE_OK)
            fatal("sqlite3_bind_value failed\n");
        status=sqlite3_step(create_virtual);
        if (status!=SQLITE_DONE)
            fatal("sqlite3_step: %s\n",sqlite3_errmsg(destination_db));
        sqlite3_reset(create_virtual);
        sqlite3_clear_bindings(create_virtual);
    }
    sqlite3_finalize(list_virtuals);
    sqlite3_finalize(create_virtual);
    run_or_die(destination_db,pragma_set_writable_schema_reset_sql);
}

static void usage(void)
{
    fputs(
        "Usage: steg3 [ options ] source_db [ destination_db ]\n"
        "  source database options:\n"
        "    -e / --extract   extract_file\n"
        "  destination database options:\n"
        "    -i / --insert    insert_file\n"
        "    -8 / --utf8\n"
        "    -N / --utf16\n"
        "    -L / --utf16le\n"
        "    -B / --utf16be\n",
        stderr);
    exit(1);
}

static void parse_args(
    int argc,
    char **argv)
{
    argc--;
    argv++;
    while (argc>0) {
        if (!strcmp(argv[0],"--")) {
            argc--;
            argv++;
            break;
        } else if (!strcmp(argv[0],"-i") || !strcmp(argv[0],"--insert")) {
            argc--;
            argv++;
            if (argc<1)
                usage();
            argc--;
            insert_name=*argv++;
        } else if (!strcmp(argv[0],"-e") || !strcmp(argv[0],"--extract")) {
            argc--;
            argv++;
            if (argc<1)
                usage();
            argc--;
            extract_name=*argv++;
        } else if (!strcmp(argv[0],"-8") || !strcmp(argv[0],"--utf8")) {
            argc--;
            argv++;
            destination_encoding=SQLITE_UTF8;
        } else if (!strcmp(argv[0],"-L") || !strcmp(argv[0],"--utf16le")) {
            argc--;
            argv++;
            destination_encoding=SQLITE_UTF16LE;
        } else if (!strcmp(argv[0],"-B") || !strcmp(argv[0],"--utf16be")) {
            argc--;
            argv++;
            destination_encoding=SQLITE_UTF16BE;
        } else if (!strcmp(argv[0],"-N") || !strcmp(argv[0],"--utf16")) {
            argc--;
            argv++;
            destination_encoding=SQLITE_UTF16;
        } else if (argv[0][0]=='-') {
            fprintf(stderr,"Unknown option %s\n",argv[0]);
            usage();
        } else {
            break;
        }
    }
    if (argc<1)
        usage();
    argc--;
    source_name=*argv++;
    if (argc>=1) {
        argc--;
        destination_name=*argv++;
    }
    if (insert_name) {
        if (!destination_name)
            fatal("Can't insert data without a destination database\n");
        if (destination_encoding==SQLITE_UTF8)
            fatal("Can't insert data into a UTF-8 database\n");
    }
}

static void pass_1(void)
{
    open_source();
    load_tables();
    open_extract();
    examine_data();
    close_extract();
    report();
}

static void pass_2(void)
{
    open_insert();
    open_destination();
    create_tables();
    copy_data();
    close_insert();
    create_objects("index");
    create_virtuals();
    create_objects("view");
    create_objects("trigger");
    close_destination();
}

int main(
    int argc,
    char **argv)
{
    parse_args(argc,argv);
    pass_1();
    if (destination_name)
        pass_2();
    close_source();
    return 0;
}

