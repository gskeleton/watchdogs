#include  "utils.h"
#include  "units.h"
#include  "crypto.h"
#include  "debug.h"
#include  "replicate.h"
#include  "cause.h"

extern causeExplanation ccs[];

static const char* dog_find_warn_err(const char* line)
{
    /* Validate input parameters */
    if (!line) {
        return (NULL);
    } /* if */
    
    if (!*line) {
        return (NULL);
    } /* if */

    /* Check line length */
    size_t line_len = strlen(line);
    if (line_len == 0) {
        return (NULL);
    } /* if */
    
    if (line_len > DOG_MAX_PATH) {
        pr_info(stdout, "dog_find_warn_err: line length %zu exceeds max %d", 
                 line_len, DOG_MAX_PATH);
        return (NULL);
    } /* if */

    /* Search through all known error patterns */
    for (int cindex = 0; ccs[cindex].cs_t != NULL; ++cindex) {
        /* Validate current pattern entry */
        if (!ccs[cindex].cs_t) {
            pr_info(stdout, "dog_find_warn_err: pattern %d has NULL text", cindex);
            continue;
        } /* if */
        
        if (!ccs[cindex].cs_i) {
            pr_info(stdout, "dog_find_warn_err: pattern %d has NULL info", cindex);
            continue;
        } /* if */

        /* Search for pattern in line */
        const char* found = strstr(line, ccs[cindex].cs_t);
        if (found) {
            size_t pattern_len = strlen(ccs[cindex].cs_t);
            
            /* Verify pattern is within line bounds */
            if ((size_t)(found - line) + pattern_len <= line_len) {
                return (ccs[cindex].cs_i);
            } else {
                ;
            } /* if */
        } /* if */
    } /* for */
    
    /* No pattern found */
    return (NULL);
} /* dog_find_warn_err */

static void pc_detailed(const char* dog_output, int debug,
    int warning_count, int error_count, const char* pc_ver,
    long int header_size, long int code_size, long int data_size,
    long int stack_size, long int total_size)
{
    char outbuf[DOG_MAX_PATH] = {0};
    int len = 0;
    
    /* Validate input parameters */
    if (dog_output == NULL) {
        pr_error(stdout, "pc_detailed: dog_output is NULL");
        return;
    } /* if */
    
    if (pc_ver == NULL) {
        pr_warning(stdout, "pc_detailed: pc_ver is NULL, using default");
        pc_ver = "";
    } /* if */

    /* Show compilation result status based on error count */
    if (error_count < 1) {
        /* Successful compilation */
        len = snprintf(outbuf, sizeof(outbuf),
            "Compilation Complete - OK! | " DOG_COL_CYAN "%d pass (warning) " DOG_COL_DEFAULT
            "| " DOG_COL_BLUE "%d fail (error)\n",
            warning_count, error_count);
        
        if (len > 0 && len < (int)sizeof(outbuf)) {
            fwrite(outbuf, 1, len, stdout);
        } /* if */
    } else {
        /* Failed compilation */
        len = snprintf(outbuf, sizeof(outbuf),
            "Compilation Complete - Fail :( | " DOG_COL_CYAN "%d pass (warning) " DOG_COL_DEFAULT
            "| " DOG_COL_BLUE "%d fail (error)\n",
            warning_count, error_count);
        
        if (len > 0 && len < (int)sizeof(outbuf)) {
            fwrite(outbuf, 1, len, stdout);
        } /* if */
    } /* if */

    /* Print separator line */
    print("-----------------------------\n");

    /* Show detailed AMX file information if available */
    if (path_exists(dog_output) && debug && error_count < 1) {
        /* Check if we have valid size information */
        if (header_size >= 1 && total_size >= 1) {
            /* Set file permissions */
            __set_default_access(dog_output);
            
            /* Calculate file hash */
            unsigned long hash = crypto_djb2_hash_file(dog_output);
            
            /* Format detailed output */
            len = snprintf(outbuf, sizeof(outbuf),
                "Output: %s\nHeader : %ldB  |  Total        : %ldB\n"
                "Code (static mem)   : %ldB  |  hash (djb2)  : %#lx\n"
                "Data (static mem)   : %ldB\nStack (automatic)   : %ldB\n",
                dog_output,
                header_size,
                total_size,
                code_size,
                hash,
                data_size,
                stack_size);
            
            if (len > 0 && len < (int)sizeof(outbuf)) {
                fwrite(outbuf, 1, len, stdout);
            } /* if */
        } else {
            pr_info(stdout, "pc_detailed: size information incomplete");
        } /* if */
    } /* if */

    /* Add newline */
    (void)putchar('\n');

    /* Show compiler version if available */
    if (pc_ver[0] != '\0') {
        len = snprintf(outbuf, sizeof(outbuf),
            "** Pawn Compiler %s - Copyright (c) 1997-2006, ITB CompuPhase\n",
            pc_ver);
        
        if (len > 0 && len < (int)sizeof(outbuf)) {
            fwrite(outbuf, 1, len, stdout);
        } /* if */
    } /* if */
} /* pc_detailed */

void cause_pc_expl(const char* log_file, const char* dog_output, int debug)
{
    FILE* _log_file = NULL;
    char pbuf[DOG_PATH_MAX] = { 0 };
    int warning_count = 0, error_count = 0;
    long int header_size = 0, code_size = 0, data_size = 0, stack_size = 0, total_size = 0;
    char pc_line[DOG_MORE_MAX_PATH] = { 0 }, pc_ver[64] = { 0 };
    int line_count = 0;
    int matched_patterns = 0;

    /* Call debugging function */
    minimal_debugging();

    /* Reset console color */
    print(DOG_COL_DEFAULT);

    /* Validate input parameters */
    if (log_file == NULL) {
        pr_error(stdout, "cause_pc_expl: log_file is NULL");
        return;
    } /* if */
    
    if (strlen(log_file) == 0) {
        pr_error(stdout, "cause_pc_expl: log_file is empty");
        return;
    } /* if */
    
    if (dog_output == NULL) {
        pr_warning(stdout, "cause_pc_expl: dog_output is NULL");
        /* Continue anyway as this might be optional */
    } /* if */

    /* Open log file for reading */
    _log_file = fopen(log_file, "r");
    if (!_log_file) {
        pr_error(stdout, "cause_pc_expl: failed to open log file: %s", log_file);
        return;
    } /* if */

    /* Process each line in the log file */
    while (fgets(pc_line, sizeof(pc_line), _log_file)) {
        line_count++;
        
        /* Remove trailing newline for cleaner output */
        size_t line_len = strlen(pc_line);
        if (line_len > 0 && pc_line[line_len - 1] == '\n') {
            pc_line[line_len - 1] = '\0';
        } /* if */

        /* Skip lines containing warning/error headers */
        if (dog_strcase(pc_line, "Warnings.") ||
            dog_strcase(pc_line, "Warning.") ||
            dog_strcase(pc_line, "Errors.") ||
            dog_strcase(pc_line, "Error.")) {
            continue;
        } /* if */

        /* Parse header size information */
        if (dog_strcase(pc_line, "Header size:") ||
            strstr(pc_line, "* Header size") != NULL)
        {
            char* colon_pos = strchr(pc_line, ':');
            if (colon_pos != NULL) {
                header_size = strtol(colon_pos + 1, NULL, 10);
            } /* if */
            continue;
        } 
        /* Parse code size information */
        else if (dog_strcase(pc_line, "Code size:") ||
            strstr(pc_line, "* Code size") != NULL)
        {
            char* colon_pos = strchr(pc_line, ':');
            if (colon_pos != NULL) {
                code_size = strtol(colon_pos + 1, NULL, 10);
            } /* if */
            continue;
        } 
        /* Parse data size information */
        else if (dog_strcase(pc_line, "Data size:") ||
            strstr(pc_line, "* Data size") != NULL)
        {
            char* colon_pos = strchr(pc_line, ':');
            if (colon_pos != NULL) {
                data_size = strtol(colon_pos + 1, NULL, 10);
            } /* if */
            continue;
        } 
        /* Parse stack/heap size information */
        else if (dog_strcase(pc_line, "Stack/heap size:") ||
            strstr(pc_line, "* Stack/heap size") != NULL)
        {
            char* colon_pos = strchr(pc_line, ':');
            if (colon_pos != NULL) {
                stack_size = strtol(colon_pos + 1, NULL, 10);
            } /* if */
            continue;
        } 
        /* Parse total requirements */
        else if (dog_strcase(pc_line, "Total requirements:") ||
            strstr(pc_line, "* Total requirements") != NULL)
        {
            char* colon_pos = strchr(pc_line, ':');
            if (colon_pos != NULL) {
                total_size = strtol(colon_pos + 1, NULL, 10);
            } /* if */
            continue;
        } 
        /* Extract compiler version */
        else if (dog_strcase(pc_line, "Pawn Compiler ")) {
            char* p = strstr(pc_line, " ");
            
            /* Skip spaces to find version number */
            if (p != NULL) {
                while (*p && !isdigit(*p)) {
                    p++;
                } /* while */
                
                if (*p) {
                    int scanned = sscanf(p, "%63s", pc_ver);
                    if (scanned == 1) {
                        ;
                    } /* if */
                } /* if */
            } /* if */
            continue;
        } /* if */

        /* Output the current line */
        int len = snprintf(pbuf, sizeof(pbuf),
            DOG_COL_BWHITE "%s\n" DOG_COL_DEFAULT, pc_line);
        
        if (len > 0 && len < (int)sizeof(pbuf)) {
            fwrite(pbuf, 1, len, stdout);
            fflush(stdout);
        } /* if */

        /* Count warnings and errors in the line */
        if (dog_strcase(pc_line, "warning")) {
            ++warning_count;
        } /* if */
        
        if (dog_strcase(pc_line, "error")) {
            ++error_count;
        } /* if */

        /* Find and display error/warning description */
        const char* description = dog_find_warn_err(pc_line);
        if (description) {
            const char* found = NULL;
            int column = 0;
            matched_patterns++;
            
            /* Find the column position of the pattern */
            for (int i = 0; ccs[i].cs_t; ++i) {
                if ((found = strstr(pc_line, ccs[i].cs_t))) {
                    const char* colon;
                    
                    /* Handle Unix-style paths */
                    if (strchr(pc_line, '/'))
                        colon = strchr(pc_line, '/');
                    /* Handle Windows-style paths */
                    else if (strchr(pc_line, '\\'))
                        colon = strchr(pc_line, '\\');
                    /* Handle simple filenames */
                    else
                        colon = strchr(pc_line, '.');
                    
                    if (colon)
                        column = colon - pc_line;
                    break;
                } /* if */
            } /* for */

            /* Print indentation */
            for (int w = 0; w < column; ++w) {
                (void)putchar(' ');
            } /* for */
            
            /* Print the description */
            pbuf[0] = '\0';
            len = snprintf(pbuf, sizeof(pbuf),
                DOG_COL_CYAN "[%s] \n" DOG_COL_DEFAULT, description);
            
            if (len > 0 && len < (int)sizeof(pbuf)) {
                fwrite(pbuf, 1, len, stdout);
                fflush(stdout);
            } /* if */
        } /* if */
    } /* while */

    /* Check if we processed any lines */
    if (line_count == 0) {
        pr_warning(stdout, "cause_pc_expl: log file is empty");
    } /* if */
    
    /* Close log file */
    fclose(_log_file);

    /* Display detailed compilation information */
    pc_detailed(dog_output, debug, warning_count, error_count,
        pc_ver, header_size, code_size,
        data_size, stack_size, total_size);
} /* cause_pc_expl */

causeExplanation ccs[] =
{
/* 001 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000001,
    COMPILER_DT_SEL0000001
},

/* 002 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000002,
    COMPILER_DT_SEL0000002
},

/* 003 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000003,
    COMPILER_DT_SEL0000003
},

/* 012 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000012,
    COMPILER_DT_SEL0000012
},

/* 014 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000014,
    COMPILER_DT_SEL0000014
},

/* 015 */  /* ERROR */
{
    COMPILER_DT_PICK000015,
    COMPILER_DT_SEL0000015
},

/* 016 */  /* ERROR */
{
    COMPILER_DT_PICK000016,
    COMPILER_DT_SEL0000016
},

/* 019 */  /* ERROR */
{
    COMPILER_DT_PICK000019,
    COMPILER_DT_SEL0000019
},

/* 020 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000020,
    COMPILER_DT_SEL0000020
},

/* 036 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000036,
    COMPILER_DT_SEL0000036
},

/* 037 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000037,
    COMPILER_DT_SEL0000037
},

/* 030 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000030,
    COMPILER_DT_SEL0000030
},

/* 027 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000027,
    COMPILER_DT_SEL0000027
},

/* 026 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000026,
    COMPILER_DT_SEL0000026
},

/* 028 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000028,
    COMPILER_DT_SEL0000028
},

/* 054 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000054,
    COMPILER_DT_SEL0000054
},

/* 004 */  /* ERROR */
{
    COMPILER_DT_PICK000004,
    COMPILER_DT_SEL0000004
},

/* 005 */  /* ERROR */
{
    COMPILER_DT_PICK000005,
    COMPILER_DT_SEL0000005
},

/* 006 */  /* ERROR */
{
    COMPILER_DT_PICK000006,
    COMPILER_DT_SEL0000006
},

/* 007 */  /* ERROR */
{
    COMPILER_DT_PICK000007,
    COMPILER_DT_SEL0000007
},

/* 008 */  /* ERROR */
{
    COMPILER_DT_PICK000008,
    COMPILER_DT_SEL0000008
},

/* 009 */  /* ERROR */
{
    COMPILER_DT_PICK000009,
    COMPILER_DT_SEL0000009
},

/* 017 */  /* ERROR */
{
    COMPILER_DT_PICK000017,
    COMPILER_DT_SEL0000017
},

/* 018 */  /* ERROR */
{
    COMPILER_DT_PICK000018,
    COMPILER_DT_SEL0000018
},

/* 022 */  /* ERROR */
{
    COMPILER_DT_PICK000022,
    COMPILER_DT_SEL0000022
},

/* 023 */  /* ERROR */
{
    COMPILER_DT_PICK000023,
    COMPILER_DT_SEL0000023
},

/* 024 */  /* ERROR */
{
    COMPILER_DT_PICK000024,
    COMPILER_DT_SEL0000024
},

/* 025 */  /* ERROR */
{
    COMPILER_DT_PICK000025,
    COMPILER_DT_SEL0000025
},

/* 027 */  /* ERROR */
{
    COMPILER_DT_PICK027,
    COMPILER_DT_SEL0000027_2
},

/* 029 */  /* ERROR */
{
    COMPILER_DT_PICK000029,
    COMPILER_DT_SEL0000029
},

/* 032 */  /* ERROR */
{
    COMPILER_DT_PICK000032,
    COMPILER_DT_SEL0000032
},

/* 045 */  /* ERROR */
{
    COMPILER_DT_PICK000045,
    COMPILER_DT_SEL0000045
},

/* 203 */  /* WARNING */
{
    COMPILER_DT_PICK000203,
    COMPILER_DT_SEL0000203
},

/* 204 */  /* WARNING */
{
    COMPILER_DT_PICK000204,
    COMPILER_DT_SEL0000204
},

/* 235 */  /* WARNING */
{
    COMPILER_DT_PICK000099,
    COMPILER_DT_SEL0000421
},

/* 205 */  /* WARNING */
{
    COMPILER_DT_PICK000205,
    COMPILER_DT_SEL0000205
},

/* 209 */  /* ERROR */
{
    COMPILER_DT_PICK000209,
    COMPILER_DT_SEL0000209
},

/* 211 */  /* WARNING */
{
    COMPILER_DT_PICK000211,
    COMPILER_DT_SEL0000211
},

/* 010 */  /* SYNTAX ERROR */
{
    COMPILER_DT_PICK000010,
    COMPILER_DT_SEL0000010
},

/* 213 */  /* ERROR */
{
    COMPILER_DT_PICK000213,
    COMPILER_DT_SEL0000213
},

/* 215 */  /* WARNING */
{
    COMPILER_DT_PICK000215,
    COMPILER_DT_SEL0000215
},

/* 217 */  /* WARNING */
{
    COMPILER_DT_PICK000217,
    COMPILER_DT_SEL0000217
},

/* 234 */  /* WARNING */
{
    COMPILER_DT_PICK000234,
    COMPILER_DT_SEL0000234
},

/* 013 */  /* ERROR */
{
    COMPILER_DT_PICK000013,
    COMPILER_DT_SEL0000013
},

/* 021 */  /* ERROR */
{
    COMPILER_DT_PICK000021,
    COMPILER_DT_SEL0000021
},

/* 028 */  /* ERROR */
{
    COMPILER_DT_PICK028,
    COMPILER_DT_SEL0000028_2
},

/* 033 */  /* ERROR */
{
    COMPILER_DT_PICK000033,
    COMPILER_DT_SEL0000033
},

/* 034 */  /* ERROR */
{
    COMPILER_DT_PICK000034,
    COMPILER_DT_SEL0000034
},

/* 035 */  /* ERROR */
{
    COMPILER_DT_PICK000035,
    COMPILER_DT_SEL0000035
},

/* 037 */  /* ERROR */
{
    COMPILER_DT_PICK037,
    COMPILER_DT_SEL0000037_2
},

/* 039 */  /* ERROR */
{
    COMPILER_DT_PICK000039,
    COMPILER_DT_SEL0000039
},

/* 040 */  /* ERROR */
{
    COMPILER_DT_PICK000040,
    COMPILER_DT_SEL0000040
},

/* 041 */  /* ERROR */
{
    COMPILER_DT_PICK000041,
    COMPILER_DT_SEL0000041
},

/* 042 */  /* ERROR */
{
    COMPILER_DT_PICK000042,
    COMPILER_DT_SEL0000042
},

/* 043 */  /* ERROR */
{
    COMPILER_DT_PICK000043,
    COMPILER_DT_SEL0000043
},

/* 044 */  /* ERROR */
{
    COMPILER_DT_PICK000044,
    COMPILER_DT_SEL0000044
},

/* 046 */  /* ERROR */
{
    COMPILER_DT_PICK000046,
    COMPILER_DT_SEL0000046
},

/* 047 */  /* ERROR */
{
    COMPILER_DT_PICK000047,
    COMPILER_DT_SEL0000047
},

/* 048 */  /* ERROR */
{
    COMPILER_DT_PICK000048,
    COMPILER_DT_SEL0000048
},

/* 049 */  /* ERROR */
{
    COMPILER_DT_PICK000049,
    COMPILER_DT_SEL0000049
},

/* 050 */  /* ERROR */
{
    COMPILER_DT_PICK000050,
    COMPILER_DT_SEL0000050
},

/* 055 */  /* ERROR */
{
    COMPILER_DT_PICK000055,
    COMPILER_DT_SEL0000055
},

/* 100 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000100,
    COMPILER_DT_SEL0000100
},

/* 101 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000101,
    COMPILER_DT_SEL0000101
},

/* 102 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000102,
    COMPILER_DT_SEL0000102
},

/* 103 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000103,
    COMPILER_DT_SEL0000103
},

/* 104 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000104,
    COMPILER_DT_SEL0000104
},

/* 105 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000105,
    COMPILER_DT_SEL0000105
},

/* 107 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000107,
    COMPILER_DT_SEL0000107
},

/* 108 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000108,
    COMPILER_DT_SEL0000108
},

/* 109 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000109,
    COMPILER_DT_SEL0000109
},

/* 110 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000110,
    COMPILER_DT_SEL0000110
},

/* 111 */  /* FATAL ERROR */
{
    COMPILER_DT_PICK000111,
    COMPILER_DT_SEL0000111
},

/* 214 */  /* WARNING */
{
    COMPILER_DT_PICK214,
    COMPILER_DT_SEL0000214
},

/* 239 */  /* WARNING */
{
    COMPILER_DT_PICK0002123,
    COMPILER_DT_SEL0000091
},

/* 200 */  /* WARNING */
{
    COMPILER_DT_PICK000200,
    COMPILER_DT_SEL0000200
},

/* 201 */  /* WARNING */
{
    COMPILER_DT_PICK000201,
    COMPILER_DT_SEL0000201
},

/* 202 */  /* WARNING */
{
    COMPILER_DT_PICK000202,
    COMPILER_DT_SEL0000202
},

/* 206 */  /* WARNING */
{
    COMPILER_DT_PICK000206,
    COMPILER_DT_SEL0000206
},

/* 214 */  /* WARNING */
{
    COMPILER_DT_PICK214_2,
    COMPILER_DT_SEL0000214_2
},

/* 060 */  /* ERROR */
{
    COMPILER_DT_PICK000060,
    COMPILER_DT_SEL0000060
},

/* 061 */  /* ERROR */
{
    COMPILER_DT_PICK000061,
    COMPILER_DT_SEL0000061
},

/* 062 */  /* ERROR */
{
    COMPILER_DT_PICK000062,
    COMPILER_DT_SEL0000062
},

/* 068 */  /* ERROR */
{
    COMPILER_DT_PICK000068,
    COMPILER_DT_SEL0000068
},

/* 069 */  /* ERROR */
{
    COMPILER_DT_PICK000069,
    COMPILER_DT_SEL0000069
},

/* 070 */  /* ERROR */
{
    COMPILER_DT_PICK000070,
    COMPILER_DT_SEL0000070
},

/* 071 */  /* ERROR */
{
    COMPILER_DT_PICK000071,
    COMPILER_DT_SEL0000071
},

/* 072 */  /* ERROR */
{
    COMPILER_DT_PICK000072,
    COMPILER_DT_SEL0000072
},

/* 038 */  /* ERROR */
{
    COMPILER_DT_PICK038,
    COMPILER_DT_SEL0000038
},

/* Sentinel value to mark the end of the array. */
{NULL, NULL}
};
