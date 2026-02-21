#ifndef PROCESS_H
#define PROCESS_H

long pc_get_milisec();
void pc_stage_trying(const char *stage, int ms);
void dog_serv_init(char *input_path, char *pawncc_path);
int dog_exec_pc_process(char *pawncc_path,
							  char *input_path,
							  char *output_path);

#endif