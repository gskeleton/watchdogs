#ifndef PROCESS_H
#define PROCESS_H

int dog_exec_compiler_tasks(char* pawncc_path,
    char* input_path,
    char* output_path);

void dog_exec_windows_server(char* binary);
void dog_exec_linux_server(char* binary);

#endif
